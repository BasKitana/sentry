"""S.E.N.T.R.Y. AUTO + APPROVAL tools: real side effects.

Every function here is registered into safety.REGISTRY as an import side
effect (via the @safety.register_tool decorator). Nothing outside this
module (and diagnostics.py / blocked.py) is allowed to touch the OS.

Defense in depth beyond the tier label: the tier gate answers "is this
category of action allowed", not "is this specific target safe" — so each
function that takes a target (pid / service name / startup item name / path)
re-validates that target itself instead of trusting the model's arguments.
"""
import os
import subprocess
import time
import winreg

import psutil
import pywintypes
import send2trash
import win32serviceutil

import diagnostics
import rollback
import safety
from safety import Tier

# ---------------------------------------------------------------------------
# Shared target-validation helpers
# ---------------------------------------------------------------------------

_PROGRAM_FILES_ENV_VARS = ("PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432")

# Directories that may be operated on *inside* but must never be targeted as a
# whole. The Windows-directory rule below is recursive (nothing under it may be
# touched); these are the opposite shape — "C:\Program Files\SomeApp\stale.log"
# is a legitimate target, "C:\Program Files" is not.
_PROTECTED_ROOT_ENV_VARS = (
    "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432",
    "PROGRAMDATA", "USERPROFILE", "PUBLIC", "ALLUSERSPROFILE",
)


def _protected_roots() -> set:
    """Normalized set of directories that must never be deleted wholesale."""
    roots = set()
    for env_var in _PROTECTED_ROOT_ENV_VARS:
        value = os.environ.get(env_var)
        if not value:
            continue
        root = os.path.normcase(os.path.normpath(value))
        roots.add(root)
        if env_var == "USERPROFILE":
            # ...and the directory holding every profile, e.g. C:\Users.
            parent = os.path.dirname(root)
            if parent and parent != root:
                roots.add(parent)
    return roots


def _is_denylisted_path(path: str) -> bool:
    """Reject any path under the Windows directory (which includes
    System32) or under Program Files\\Windows* (e.g. WindowsApps, Windows
    Defender, Windows Media Player). Shared by every tool that deletes or
    moves a file, regardless of tier.

    Deliberately conservative about how it gets there, because the check
    below is a plain string comparison on a normalized path and several
    path spellings are trivial for a model (or a user prompt) to produce
    that resolve to the exact same file on disk without ever containing
    "Windows" as a normal path component:
      - the "\\\\?\\" extended-length / local-device prefix (e.g.
        "\\\\?\\C:\\Windows\\System32\\...") is stripped before comparison,
        since the file APIs used to actually act on the path (send2trash,
        os.remove) honor it identically to the unprefixed form.
      - any remaining UNC-style path (a literal "\\\\server\\share\\..."
        path, including via a local admin share like
        "\\\\localhost\\C$\\Windows\\...", which reaches System32 with no
        drive-letter prefix at all) is refused outright — these tools have
        no legitimate need to touch a network path.
      - os.path.realpath (not just abspath) is used so an 8.3 short name
        (e.g. "C:\\PROGRA~1") or a symlink/junction resolves to its real,
        canonical target before comparison instead of evading it.

    Beyond the recursive Windows-directory rule, whole-container targets are
    refused too: a drive root ("C:\\") and the roots of Program Files,
    ProgramData, C:\\Users and the user's own profile. Those are not covered by
    the recursive rules — a prefix test of the form "starts with <dir>\\" never
    matches <dir> itself — so without this, move_to_recycle_bin (which takes
    folders as well as files) would accept "C:\\Program Files" or the entire
    user profile as a target. move_to_recycle_bin is APPROVAL tier (not AUTO)
    precisely because Recycle Bin isn't a full safety net for a folder-sized
    target — it silently permanent-deletes instead if disabled or over quota
    — so this denylist is defense in depth, not the only guard.
    """
    try:
        raw = str(path)
        if raw.startswith("\\\\?\\") or raw.startswith("//?/"):
            raw = raw[4:]
        if raw.startswith("\\\\") or raw.startswith("//") or raw.upper().startswith("UNC\\"):
            return True  # network / admin-share path -> refuse, don't try to canonicalize it

        norm = os.path.normcase(os.path.normpath(os.path.realpath(raw)))
    except (OSError, ValueError):
        return True  # can't even normalize it -> treat as unsafe

    windir = os.path.normcase(os.path.normpath(os.environ.get("WINDIR", r"C:\Windows")))
    if norm == windir or norm.startswith(windir + os.sep):
        return True

    # A drive root ("C:\", "D:\"): deleting or recycling an entire volume is
    # never a legitimate repair action.
    drive, tail = os.path.splitdrive(norm)
    if drive and tail in ("", os.sep, "/"):
        return True

    if norm in _protected_roots():
        return True

    for env_var in _PROGRAM_FILES_ENV_VARS:
        pf = os.environ.get(env_var)
        if not pf:
            continue
        prefix = os.path.normcase(os.path.normpath(pf)) + os.sep
        if norm.startswith(prefix):
            top_level = norm[len(prefix):].split(os.sep, 1)[0]
            if top_level.startswith("windows"):
                return True

    return False


_CRITICAL_PROCESS_NAMES = {
    "explorer.exe", "winlogon.exe", "csrss.exe", "services.exe", "system",
    "system idle process", "smss.exe", "wininit.exe", "lsass.exe",
}


# ---------------------------------------------------------------------------
# Prechecks — run by safety.dispatch() BEFORE the approval prompt and before
# any rollback point is created. Each takes the tool_input dict and returns a
# refusal result, or None to let the call proceed. The tools below still
# repeat these checks internally; this is an extra early gate, not a
# replacement for that defense in depth.
# ---------------------------------------------------------------------------

def _precheck_path(tool_input: dict):
    path = tool_input.get("path")
    if path is not None and _is_denylisted_path(path):
        return {"error": True, "message": f"Refused: '{path}' is under a protected system directory."}
    return None


def _precheck_process(tool_input: dict):
    pid = tool_input.get("pid")
    if pid is None:
        return None
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return {"error": True, "message": f"No process with PID {pid} found. It may have already exited."}
    except (ValueError, TypeError):
        return {"error": True, "message": f"Refused: {pid!r} is not a valid process ID."}

    try:
        name = proc.name()
    except psutil.NoSuchProcess:
        return {"error": True, "message": f"No process with PID {pid} found. It may have already exited."}
    except psutil.AccessDenied:
        return {
            "error": True,
            "message": f"Refused: the name of PID {pid} could not be read (access denied), so it "
                       f"cannot be checked against the critical-OS-process list.",
        }

    if name.lower() in _CRITICAL_PROCESS_NAMES:
        return {
            "error": True,
            "message": f"Refused: PID {pid} is '{name}', a critical OS process. Acting on it could "
                       f"crash or lock up the system. There is no override.",
        }
    return None


def _precheck_not_implemented(tool_input: dict):
    """Refuse the unimplemented stubs up front. Without this they ran the full
    approval machinery — prompting the user and creating a System Restore
    point — only to return 'not implemented', wasting the once-per-24h
    restore point on an action that never happened."""
    return dict(_NOT_IMPLEMENTED)


# Real, well-known Windows power scheme GUIDs (not model-guessable/free-form —
# verified against Microsoft's own powercfg documentation, which uses the
# Balanced GUID below in its own worked examples: https://learn.microsoft.com/
# en-us/windows-hardware/design/device-experiences/powercfg-command-line-options).
# set_power_plan() only ever accepts one of these three named keys; the GUID
# on the wire is never taken from the model.
_POWER_PLAN_GUIDS = {
    "high_performance": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
    "balanced": "381b4222-f694-41f0-9685-ff5bb260df2e",
    "power_saver": "a1841308-3541-4fab-bc81-f71556f20b4a",
}


def _precheck_power_plan(tool_input: dict):
    plan = tool_input.get("plan")
    if plan not in _POWER_PLAN_GUIDS:
        return {
            "error": True,
            "message": f"Refused: {plan!r} is not on the power-plan allowlist "
                       f"({', '.join(sorted(_POWER_PLAN_GUIDS))}).",
        }
    return None


def _normalize_drive_letter(drive) -> str:
    """'C:', 'C:\\\\', 'c', 'C:/' -> 'C:'. Not itself a safety check — just
    shape normalization so the same drive can be compared against psutil's
    partition list regardless of how it was spelled."""
    d = str(drive or "").strip().rstrip("\\/")
    if len(d) == 1 and d.isalpha():
        d += ":"
    return d.upper()


def _find_fixed_drive(drive):
    """Return psutil's partition info for `drive` iff it is a currently-
    mounted, local FIXED drive — never a network/remote share, optical
    drive, removable drive, or a drive letter that isn't actually mounted.
    Queried fresh every call (never trusts the model's string on its own).
    `all=True` so remote/removable/cdrom drives are actually present in the
    list to be positively rejected by the opts check, rather than relying on
    psutil's own default filtering to keep them out."""
    target = _normalize_drive_letter(drive)
    if not target:
        return None
    try:
        partitions = psutil.disk_partitions(all=True)
    except OSError:
        return None
    for part in partitions:
        if _normalize_drive_letter(part.device) != target:
            continue
        if "fixed" in (part.opts or "").split(","):
            return part
    return None


def _precheck_drive(tool_input: dict):
    drive = tool_input.get("drive")
    if not isinstance(drive, str) or not drive.strip():
        return {"error": True, "message": "Refused: 'drive' must be a non-empty drive string (e.g. 'C:')."}
    if _find_fixed_drive(drive) is None:
        return {
            "error": True,
            "message": f"Refused: {drive!r} is not a currently-mounted local fixed drive. "
                       f"Network drives, removable media, and optical drives are not supported.",
        }
    return None


# ---------------------------------------------------------------------------
# AUTO tools
# ---------------------------------------------------------------------------

@safety.register_tool(
    name="restart_unresponsive_process",
    description=(
        "Force-terminate a hung/unresponsive process and relaunch it from its original "
        "executable path. Call when the user reports a specific application is frozen or "
        "not responding, after confirming its PID via list_processes()."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "pid": {"type": "integer", "description": "Process ID of the unresponsive process, from list_processes()."}
        },
        "required": ["pid"],
    },
    tier=Tier.AUTO,
    is_action=True,
)
def restart_unresponsive_process(pid: int) -> dict:
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return {"error": True, "message": f"No process with PID {pid} found. It may have already exited."}

    # The critical-process check is only as good as the name behind it, so an
    # unreadable name has to be a refusal, not a shrug — psutil raises
    # AccessDenied for exactly the kind of protected process this guard exists
    # to protect. (Unguarded, this call also escaped as an exception and took
    # the whole session down.)
    try:
        name = proc.name()
    except psutil.NoSuchProcess:
        return {"error": True, "message": f"No process with PID {pid} found. It may have already exited."}
    except psutil.AccessDenied:
        return {
            "error": True,
            "message": f"Refused: the name of PID {pid} could not be read (access denied), so it "
                       f"cannot be checked against the critical-OS-process list. Refusing rather "
                       f"than terminating an unidentified process.",
        }

    if name.lower() in _CRITICAL_PROCESS_NAMES:
        return {
            "error": True,
            "message": f"Refused: PID {pid} is '{name}', a critical OS process. Terminating it "
                       f"could crash or lock up the system. This tool is only for hung user "
                       f"applications, not system processes — there is no override.",
        }

    try:
        exe = proc.exe()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        exe = None

    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    except psutil.NoSuchProcess:
        pass
    except psutil.AccessDenied:
        return {"error": True, "message": f"Access denied terminating PID {pid} ({name})."}

    if not exe:
        return {
            "terminated": True, "relaunched": False, "pid": pid, "name": name,
            "message": f"Terminated {name} (PID {pid}) but could not determine its executable "
                       f"path to relaunch it. Please relaunch it manually.",
        }

    try:
        new_proc = subprocess.Popen([exe])
    except OSError as e:
        return {
            "terminated": True, "relaunched": False, "pid": pid, "name": name,
            "message": f"Terminated {name} (PID {pid}) but failed to relaunch it: {e}",
        }

    return {
        "terminated": True, "relaunched": True, "pid": pid, "name": name,
        "new_pid": new_proc.pid,
        "message": f"Terminated {name} (PID {pid}) and relaunched it (new PID {new_proc.pid}).",
    }


_SERVICE_ALLOWLIST = {"Spooler", "WSearch", "Dnscache", "wuauserv"}


@safety.register_tool(
    name="restart_windows_service",
    description=(
        "Restart a known-safe Windows service by its short service name. Only a small "
        "hardcoded allowlist can be restarted this way: Spooler (Print Spooler), "
        "WSearch (Windows Search), Dnscache (DNS Client), wuauserv (Windows Update). "
        "Any other name is refused."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Short service name, e.g. 'Spooler'. Must be on the allowlist."}
        },
        "required": ["name"],
    },
    tier=Tier.AUTO,
    is_action=True,
)
def restart_windows_service(name: str) -> dict:
    if name not in _SERVICE_ALLOWLIST:
        return {
            "error": True,
            "message": f"Refused: '{name}' is not on the restartable-service allowlist "
                       f"({', '.join(sorted(_SERVICE_ALLOWLIST))}).",
        }
    try:
        win32serviceutil.RestartService(name)
    except pywintypes.error as e:
        return {"error": True, "message": f"Failed to restart service '{name}': {e}"}
    except Exception as e:  # noqa: BLE001 - win32serviceutil can surface other error types
        return {"error": True, "message": f"Failed to restart service '{name}': {e}"}

    return {"restarted": True, "service": name, "message": f"Service '{name}' restarted."}


def _dir_size(path: str) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for fname in files:
            try:
                total += os.path.getsize(os.path.join(root, fname))
            except OSError:
                pass
    return total


@safety.register_tool(
    name="clear_temp_files",
    description=(
        "Delete files and folders in the current user's temporary files folder (%TEMP%) to "
        "free disk space. Silently skips anything currently in use (e.g. locked by a running "
        "program). Call after get_temp_file_info() when temp files are a meaningful chunk of "
        "used disk space."
    ),
    input_schema={"type": "object", "properties": {}, "required": []},
    tier=Tier.AUTO,
    is_action=True,
)
def clear_temp_files() -> dict:
    temp_dir = os.environ.get("TEMP") or os.environ.get("TMP")
    if not temp_dir:
        import tempfile
        temp_dir = tempfile.gettempdir()

    freed_bytes = 0
    deleted = 0
    skipped = 0

    try:
        entries = list(os.scandir(temp_dir))
    except OSError as e:
        return {"error": True, "message": f"Could not read temp directory '{temp_dir}': {e}"}

    for entry in entries:
        try:
            if entry.is_dir(follow_symlinks=False):
                size = _dir_size(entry.path)
                import shutil
                shutil.rmtree(entry.path)
            else:
                size = entry.stat().st_size
                os.remove(entry.path)
            freed_bytes += size
            deleted += 1
        except OSError:
            skipped += 1

    freed_mb = round(freed_bytes / 2**20, 2)
    return {
        "cleared": True, "temp_dir": temp_dir, "items_deleted": deleted,
        "items_skipped_in_use": skipped, "freed_mb": freed_mb,
        "message": f"Cleared {deleted} item(s) from {temp_dir}, freed ~{freed_mb} MB. "
                   f"Skipped {skipped} in-use item(s).",
    }


@safety.register_tool(
    name="flush_dns",
    description=(
        "Flush the Windows DNS resolver cache. Call for DNS-related connectivity issues "
        "(a site loads by IP but not by name, stale DNS records after a network change, etc.)."
    ),
    input_schema={"type": "object", "properties": {}, "required": []},
    tier=Tier.AUTO,
    is_action=True,
)
def flush_dns() -> dict:
    try:
        proc = subprocess.run(
            ["ipconfig", "/flushdns"], capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": True, "message": f"Failed to flush DNS: {e}"}

    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        return {"error": True, "message": f"ipconfig /flushdns exited with code {proc.returncode}: {detail}"}

    return {"flushed": True, "message": "DNS resolver cache flushed."}


_STARTUP_APPROVED_BASE = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"


def _startup_approved_key_for_location(location: str):
    """Map a Win32_StartupCommand .Location string to (hive, subkey) under
    StartupApproved. Returns None for a location this tool can't map to a
    Run/Run32 registry value (e.g. Startup Folder shortcuts)."""
    loc = (location or "").upper()
    if "HKLM" in loc or "LOCAL MACHINE" in loc:
        hive = winreg.HKEY_LOCAL_MACHINE
    elif "HKCU" in loc or "CURRENT USER" in loc:
        hive = winreg.HKEY_CURRENT_USER
    else:
        return None
    sub = "Run32" if "WOW6432NODE" in loc else "Run"
    return hive, f"{_STARTUP_APPROVED_BASE}\\{sub}"


def _filetime_now_bytes() -> bytes:
    # Windows FILETIME: 100-ns intervals since 1601-01-01, little-endian u64.
    epoch_diff_100ns = 116444736000000000
    filetime = int(time.time() * 10_000_000) + epoch_diff_100ns
    return filetime.to_bytes(8, "little")


def _backup_startup_flag(name: str, old_bytes: bytes) -> dict:
    dest_dir = os.path.join(rollback.BACKUP_ROOT, time.strftime("%Y%m%d-%H%M%S"))
    try:
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, f"startup_{name}.hex")
        with open(dest, "w", encoding="utf-8") as f:
            f.write(old_bytes.hex())
        return {"backed_up": True, "path": dest}
    except OSError as e:
        return {"backed_up": False, "error": str(e)}


@safety.register_tool(
    name="set_startup_item_enabled",
    description=(
        "Enable or disable a Windows startup item (an app that launches at sign-in) via the "
        "StartupApproved registry flag, without deleting its Run-key entry. `name` MUST be a "
        "name exactly as returned by list_startup_items() — arbitrary names are rejected."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Startup item name, exactly as returned by list_startup_items()."},
            "enabled": {"type": "boolean", "description": "True to enable at next sign-in, False to disable."},
        },
        "required": ["name", "enabled"],
    },
    tier=Tier.AUTO,
    is_action=True,
)
def set_startup_item_enabled(name: str, enabled: bool) -> dict:
    try:
        items = diagnostics.list_startup_items().get("items", [])
    except Exception as e:  # noqa: BLE001 - defensive: never let this crash the loop
        return {"error": True, "message": f"Could not verify startup items: {e}"}

    match = next((item for item in items if item.get("name") == name), None)
    if match is None:
        return {"error": True, "message": f"Refused: '{name}' was not found in list_startup_items() output."}

    mapped = _startup_approved_key_for_location(match.get("location", ""))
    if mapped is None:
        return {
            "error": True,
            "message": f"'{name}' is not a Run-key startup item this tool can toggle "
                       f"(location: {match.get('location')!r}).",
        }
    hive, subkey = mapped

    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE)
    except OSError as e:
        return {"error": True, "message": f"Could not open StartupApproved registry key: {e}"}

    try:
        try:
            old_value, value_type = winreg.QueryValueEx(key, name)
        except FileNotFoundError:
            return {"error": True, "message": f"No StartupApproved entry named '{name}' found under {subkey}."}

        old_bytes = bytes(old_value)
        length = max(len(old_bytes), 1)
        backup = _backup_startup_flag(name, old_bytes)

        if enabled:
            new_bytes = bytes([0x02]) + bytes(length - 1)
        else:
            payload = bytes([0x03]) + bytes(3) + _filetime_now_bytes()
            new_bytes = (payload + bytes(length))[:length]

        try:
            winreg.SetValueEx(key, name, 0, value_type, new_bytes)
            winreg.FlushKey(key)
            readback_value, _ = winreg.QueryValueEx(key, name)
        except OSError as e:
            return {"error": True, "message": f"Failed writing StartupApproved flag for '{name}': {e}", "backup": backup}
    finally:
        winreg.CloseKey(key)

    confirmed = bytes(readback_value) == new_bytes
    return {
        "changed": True, "confirmed": confirmed, "name": name, "enabled": enabled,
        "backup": backup,
        "message": (
            f"Set '{name}' to {'enabled' if enabled else 'disabled'} at next sign-in "
            f"({'confirmed on read-back' if confirmed else 'WARNING: read-back did not match what was written'})."
        ),
    }


@safety.register_tool(
    name="move_to_recycle_bin",
    description=(
        "Move a file or folder to the Windows Recycle Bin (recoverable — not permanent). "
        "Refuses paths under protected Windows system directories."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Absolute path to the file or folder to move to the Recycle Bin."}
        },
        "required": ["path"],
    },
    tier=Tier.APPROVAL,
    is_action=True,
    precheck=_precheck_path,
)
def move_to_recycle_bin(path: str) -> dict:
    if _is_denylisted_path(path):
        return {"error": True, "message": f"Refused: '{path}' is under a protected system directory."}
    if not os.path.exists(path):
        return {"error": True, "message": f"Path does not exist: {path}"}

    try:
        send2trash.send2trash(path)
    except Exception as e:  # noqa: BLE001 - send2trash's exception types vary by backend
        return {"error": True, "message": f"Failed to move '{path}' to the Recycle Bin: {e}"}

    return {"moved_to_recycle_bin": True, "path": path, "message": f"Moved '{path}' to the Recycle Bin."}


# ---------------------------------------------------------------------------
# APPROVAL tools
# ---------------------------------------------------------------------------

@safety.register_tool(
    name="permanently_delete_file",
    description=(
        "Permanently delete a single file — bypasses the Recycle Bin, cannot be undone via "
        "Explorer. A file backup rollback point is created first. Refuses paths under "
        "protected Windows system directories."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Absolute path to the file to permanently delete."}
        },
        "required": ["path"],
    },
    tier=Tier.APPROVAL,
    is_action=True,
    precheck=_precheck_path,
)
def permanently_delete_file(path: str) -> dict:
    if _is_denylisted_path(path):
        return {"error": True, "message": f"Refused: '{path}' is under a protected system directory."}
    if not os.path.isfile(path):
        return {"error": True, "message": f"Not a file (or does not exist): {path}"}

    try:
        os.remove(path)
    except OSError as e:
        return {"error": True, "message": f"Failed to delete '{path}': {e}"}

    return {"deleted": True, "path": path, "message": f"Permanently deleted '{path}'."}


@safety.register_tool(
    name="kill_process",
    description=(
        "Force-kill a process by PID. Refuses critical OS processes (explorer.exe, "
        "winlogon.exe, csrss.exe, services.exe, System, etc). Prefer "
        "restart_unresponsive_process for a hung user application when a clean relaunch is "
        "wanted instead of just killing it."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "pid": {"type": "integer", "description": "Process ID to kill, from list_processes()."}
        },
        "required": ["pid"],
    },
    tier=Tier.APPROVAL,
    is_action=True,
    precheck=_precheck_process,
)
def kill_process(pid: int) -> dict:
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return {"error": True, "message": f"No process with PID {pid} found. It may have already exited."}

    # Fail closed: an unreadable name previously fell back to "", which is not
    # in the denylist and so sailed straight past the check below into
    # proc.kill(). psutil raises AccessDenied precisely for protected system
    # processes, i.e. the ones this guard exists to stop.
    try:
        proc_name = proc.name()
    except psutil.NoSuchProcess:
        return {"error": True, "message": f"No process with PID {pid} found. It may have already exited."}
    except psutil.AccessDenied:
        return {
            "error": True,
            "message": f"Refused: the name of PID {pid} could not be read (access denied), so it "
                       f"cannot be checked against the critical-OS-process list. Refusing rather "
                       f"than killing an unidentified process.",
        }

    if proc_name.lower() in _CRITICAL_PROCESS_NAMES:
        return {
            "error": True,
            "message": f"Refused: PID {pid} is '{proc_name}', a critical OS process. "
                       f"Killing it could crash or lock up the system.",
        }

    try:
        proc.kill()
        proc.wait(timeout=5)
    except psutil.NoSuchProcess:
        return {"killed": True, "pid": pid, "name": proc_name, "message": f"Process '{proc_name}' (PID {pid}) exited."}
    except psutil.AccessDenied:
        return {"error": True, "message": f"Access denied killing PID {pid} ('{proc_name}')."}
    except psutil.TimeoutExpired:
        return {"error": True, "message": f"Sent kill signal to PID {pid} ('{proc_name}') but it did not exit within 5s."}

    return {"killed": True, "pid": pid, "name": proc_name, "message": f"Killed process '{proc_name}' (PID {pid})."}


@safety.register_tool(
    name="set_power_plan",
    description=(
        "Switch the active Windows power plan. `plan` must be one of a fixed allowlist: "
        "'high_performance' (max performance, more power draw/heat/fan noise — helps a system "
        "that feels sluggish, especially on a laptop stuck on a battery-saving plan while "
        "plugged in), 'balanced' (Windows' default performance/power trade-off), or "
        "'power_saver' (max battery life, reduced performance). Runs 'powercfg /setactive "
        "<guid>' with the real Windows-defined GUID for the chosen plan. Any other value is "
        "refused before the user is even asked to approve it."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "plan": {
                "type": "string",
                "enum": ["high_performance", "balanced", "power_saver"],
                "description": "Which power plan to activate.",
            },
        },
        "required": ["plan"],
    },
    tier=Tier.APPROVAL,
    is_action=True,
    precheck=_precheck_power_plan,
)
def set_power_plan(plan: str) -> dict:
    guid = _POWER_PLAN_GUIDS.get(plan)
    if guid is None:
        return {
            "error": True,
            "message": f"Refused: {plan!r} is not on the power-plan allowlist "
                       f"({', '.join(sorted(_POWER_PLAN_GUIDS))}).",
        }

    before = diagnostics.get_power_plan()

    try:
        proc = subprocess.run(
            ["powercfg", "/setactive", guid], capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": True, "message": f"Failed to switch power plan: {e}"}

    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        return {
            "error": True,
            "message": f"'powercfg /setactive {guid}' exited with code {proc.returncode}: {detail}",
        }

    after = diagnostics.get_power_plan()
    return {
        "changed": True, "plan": plan, "guid": guid,
        "before": before, "after": after,
        "message": f"Switched active power plan to '{plan}' ({guid}).",
    }


_VISUAL_EFFECTS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
_VISUAL_FX_SETTING_NAME = "VisualFXSetting"
_VISUAL_FX_BEST_PERFORMANCE = 2   # "Adjust for best performance" in the Performance Options UI
_VISUAL_FX_LET_WINDOWS_CHOOSE = 0  # the Windows default, before a user ever touches this setting


def _backup_visual_fx_setting(old_value) -> dict:
    dest_dir = os.path.join(rollback.BACKUP_ROOT, time.strftime("%Y%m%d-%H%M%S"))
    try:
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, "visualfxsetting.txt")
        with open(dest, "w", encoding="utf-8") as f:
            f.write("" if old_value is None else str(old_value))
        return {"backed_up": True, "path": dest}
    except OSError as e:
        return {"backed_up": False, "error": str(e)}


@safety.register_tool(
    name="set_visual_effects_for_performance",
    description=(
        "Toggle Windows' 'Adjust for best performance' visual-effects setting (the same option "
        "System Properties > Advanced > Performance Settings exposes), via the VisualFXSetting "
        "registry value under HKCU...Explorer\\VisualEffects. enabled=True disables window "
        "animations, transparency, shadows, and other UI effects for a snappier-feeling but "
        "plainer-looking desktop — worth trying on a system that feels laggy, especially with "
        "an older/integrated GPU. enabled=False restores Windows' default ('Let Windows choose "
        "what's best for my computer'). Explorer may need a sign-out/restart to fully reflect "
        "the change everywhere."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "enabled": {
                "type": "boolean",
                "description": "True for 'best performance' (disable visual effects); False to restore the Windows default.",
            },
        },
        "required": ["enabled"],
    },
    tier=Tier.APPROVAL,
    is_action=True,
)
def set_visual_effects_for_performance(enabled: bool) -> dict:
    try:
        key = winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, _VISUAL_EFFECTS_KEY, 0, winreg.KEY_READ | winreg.KEY_WRITE
        )
    except OSError as e:
        return {"error": True, "message": f"Could not open/create the VisualEffects registry key: {e}"}

    try:
        try:
            old_value, _ = winreg.QueryValueEx(key, _VISUAL_FX_SETTING_NAME)
        except FileNotFoundError:
            old_value = None  # key exists but the value has never been explicitly set

        backup = _backup_visual_fx_setting(old_value)
        new_value = _VISUAL_FX_BEST_PERFORMANCE if enabled else _VISUAL_FX_LET_WINDOWS_CHOOSE

        try:
            winreg.SetValueEx(key, _VISUAL_FX_SETTING_NAME, 0, winreg.REG_DWORD, new_value)
            winreg.FlushKey(key)
            readback_value, _ = winreg.QueryValueEx(key, _VISUAL_FX_SETTING_NAME)
        except OSError as e:
            return {
                "error": True,
                "message": f"Failed writing VisualFXSetting: {e}",
                "backup": backup,
            }
    finally:
        winreg.CloseKey(key)

    confirmed = readback_value == new_value
    target_label = "best performance" if enabled else "the Windows default ('Let Windows choose')"
    return {
        "changed": True, "confirmed": confirmed, "enabled": enabled,
        "before": old_value, "after": readback_value,
        "backup": backup,
        "message": (
            f"Set visual effects to {target_label} "
            f"({'confirmed on read-back' if confirmed else 'WARNING: read-back did not match what was written'}). "
            f"Sign out or restart apps for the change to fully apply everywhere."
        ),
    }


@safety.register_tool(
    name="optimize_drive",
    description=(
        "Run Windows' modern built-in drive optimizer ('defrag <drive> /O'), which auto-detects "
        "the media type and does the right thing — defragments a traditional HDD, or retrims an "
        "SSD/NVMe drive — without the caller needing to know which. Helps with a drive that "
        "feels slow due to fragmentation (HDD) or with reclaiming SSD write performance over "
        "time (retrim). Only a real, currently-mounted local FIXED drive is accepted; network "
        "drives, removable media, and optical drives are refused. Can take a while on a large "
        "or heavily fragmented drive."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "drive": {"type": "string", "description": "Drive letter to optimize, e.g. 'C:'."},
        },
        "required": ["drive"],
    },
    tier=Tier.APPROVAL,
    is_action=True,
    precheck=_precheck_drive,
)
def optimize_drive(drive: str) -> dict:
    part = _find_fixed_drive(drive)
    if part is None:
        return {
            "error": True,
            "message": f"Refused: {drive!r} is not a currently-mounted local fixed drive.",
        }

    letter = _normalize_drive_letter(drive)
    try:
        proc = subprocess.run(
            ["defrag", letter, "/O"], capture_output=True, text=True, timeout=1800,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": True, "message": f"Failed to run drive optimization on '{letter}': {e}"}

    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        return {
            "error": True,
            "message": f"'defrag {letter} /O' exited with code {proc.returncode}: {detail}",
        }

    return {
        "optimized": True, "drive": letter,
        "message": f"Optimized '{letter}' (auto-detected: HDD defrag or SSD retrim, whichever applies).",
        "output": proc.stdout.strip(),
    }


_WINDOWS_UPDATE_SERVICE = "wuauserv"


@safety.register_tool(
    name="clear_windows_update_cache",
    description=(
        "Run Microsoft's standard Windows Update repair steps: stop the Windows Update service "
        "(wuauserv), delete the contents of %WINDIR%\\SoftwareDistribution\\Download (the "
        "downloaded-but-not-yet-installed update cache), then restart the service. This can "
        "reclaim significant disk space and clear a stuck or corrupted update download; Windows "
        "will simply re-download anything it still needs. Call when Windows Update is stuck or "
        "failing repeatedly, or when get_windows_update_cache_size() shows a large cache."
    ),
    input_schema={"type": "object", "properties": {}, "required": []},
    tier=Tier.APPROVAL,
    is_action=True,
)
def clear_windows_update_cache() -> dict:
    download_dir = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "SoftwareDistribution", "Download")

    try:
        win32serviceutil.StopService(_WINDOWS_UPDATE_SERVICE)
    except pywintypes.error as e:
        return {"error": True, "message": f"Failed to stop '{_WINDOWS_UPDATE_SERVICE}': {e}"}
    except Exception as e:  # noqa: BLE001 - win32serviceutil can surface other error types
        return {"error": True, "message": f"Failed to stop '{_WINDOWS_UPDATE_SERVICE}': {e}"}

    freed_bytes = 0
    deleted = 0
    skipped = 0
    scan_error = None
    try:
        entries = list(os.scandir(download_dir))
    except OSError as e:
        entries = []
        scan_error = str(e)

    for entry in entries:
        try:
            if entry.is_dir(follow_symlinks=False):
                size = _dir_size(entry.path)
                import shutil
                shutil.rmtree(entry.path)
            else:
                size = entry.stat().st_size
                os.remove(entry.path)
            freed_bytes += size
            deleted += 1
        except OSError:
            skipped += 1

    try:
        win32serviceutil.StartService(_WINDOWS_UPDATE_SERVICE)
        restart_error = None
    except pywintypes.error as e:
        restart_error = str(e)
    except Exception as e:  # noqa: BLE001
        restart_error = str(e)

    freed_mb = round(freed_bytes / 2**20, 2)
    result = {
        "cleared": True,
        "download_dir": download_dir,
        "items_deleted": deleted,
        "items_skipped": skipped,
        "freed_mb": freed_mb,
        "service_restarted": restart_error is None,
        "message": (
            f"Cleared {deleted} item(s) from '{download_dir}' (~{freed_mb} MB freed), "
            f"skipped {skipped} in-use/inaccessible item(s). "
            + (f"Restarted '{_WINDOWS_UPDATE_SERVICE}'."
               if restart_error is None
               else f"WARNING: failed to restart '{_WINDOWS_UPDATE_SERVICE}': {restart_error}. "
                    f"Windows Update is left stopped — restart it manually (services.msc).")
        ),
    }
    if scan_error:
        result["scan_error"] = scan_error
    if restart_error:
        result["error"] = True
    return result


@safety.register_tool(
    name="run_component_cleanup",
    description=(
        "Run DISM component-store cleanup ('Dism.exe /online /Cleanup-Image "
        "/StartComponentCleanup') to remove superseded versions of Windows Update components "
        "from the WinSxS component store, freeing disk space. Deliberately does NOT use "
        "/ResetBase, so previously installed updates can still be uninstalled afterward if "
        "needed. Can take several minutes. Call when disk space is low and the component "
        "store/WinSxS looks like a meaningful contributor."
    ),
    input_schema={"type": "object", "properties": {}, "required": []},
    tier=Tier.APPROVAL,
    is_action=True,
)
def run_component_cleanup() -> dict:
    try:
        proc = subprocess.run(
            ["Dism.exe", "/online", "/Cleanup-Image", "/StartComponentCleanup"],
            capture_output=True, text=True, timeout=1800,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": True, "message": f"Failed to run DISM component cleanup: {e}"}

    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        return {
            "error": True,
            "message": f"DISM component cleanup exited with code {proc.returncode}: {detail}",
        }

    return {
        "cleaned_up": True,
        "message": "DISM component cleanup completed — superseded Windows Update components removed from the component store.",
        "output": proc.stdout.strip(),
    }


# ---------------------------------------------------------------------------
# Registry-only stubs (APPROVAL tier, not implemented yet)
# ---------------------------------------------------------------------------

_NOT_IMPLEMENTED = {"error": True, "message": "Not implemented in this version — please do this manually for now."}


@safety.register_tool(
    name="install_software",
    description="Install a software package. NOT IMPLEMENTED in this version — will report an error.",
    input_schema={
        "type": "object",
        "properties": {"name": {"type": "string", "description": "Name or identifier of the software to install."}},
        "required": ["name"],
    },
    tier=Tier.APPROVAL,
    is_action=True,
    precheck=_precheck_not_implemented,
)
def install_software(name: str = "") -> dict:
    return dict(_NOT_IMPLEMENTED)


@safety.register_tool(
    name="uninstall_software",
    description="Uninstall a software package. NOT IMPLEMENTED in this version — will report an error.",
    input_schema={
        "type": "object",
        "properties": {"name": {"type": "string", "description": "Name or identifier of the software to uninstall."}},
        "required": ["name"],
    },
    tier=Tier.APPROVAL,
    is_action=True,
    precheck=_precheck_not_implemented,
)
def uninstall_software(name: str = "") -> dict:
    return dict(_NOT_IMPLEMENTED)


@safety.register_tool(
    name="rollback_driver",
    description="Roll a device driver back to its previous version. NOT IMPLEMENTED in this version — will report an error.",
    input_schema={
        "type": "object",
        "properties": {"device": {"type": "string", "description": "Device or driver name to roll back."}},
        "required": ["device"],
    },
    tier=Tier.APPROVAL,
    is_action=True,
    precheck=_precheck_not_implemented,
)
def rollback_driver(device: str = "") -> dict:
    return dict(_NOT_IMPLEMENTED)
