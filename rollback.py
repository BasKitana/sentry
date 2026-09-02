"""S.E.N.T.R.Y. rollback mechanism: System Restore point + file backup.

Every APPROVAL-tier tool call gets a rollback point created before it
executes (see safety.dispatch()), so a mistake can be undone. There is no
built-in Python API for System Restore — the actual mechanism is the WMI
`SystemRestore` class's `CreateRestorePoint` method (the same call
`Checkpoint-Computer` wraps), reached here via pywin32.

Note: creating a System Restore point needs an elevated process, and
Windows allows ~1 restore point per 24h by default
(SystemRestorePointCreationFrequency) — a second call within that window
fails. dispatch() already treats that failure as an expected outcome (an
extra explicit confirmation before proceeding without a fresh safety net)
rather than silently proceeding as if one exists when it doesn't.
"""

import os, shutil, time
from dataclasses import dataclass
import win32com.client, pywintypes

BACKUP_ROOT = os.path.join(os.environ.get("LOCALAPPDATA", "."), "SENTRY", "backups")


@dataclass
class RollbackResult:
    failed: bool
    method: str          # "system_restore" | "file_backup"
    detail: str
    backup_path: str | None = None


def create_system_restore_point(description: str, restore_point_type: int = 12) -> RollbackResult:
    try:
        sr = win32com.client.GetObject(r"winmgmts:root\default:SystemRestore")
        hresult = sr.CreateRestorePoint(description, restore_point_type, 100)  # 100 = BEGIN_SYSTEM_CHANGE
        if hresult == 0:
            return RollbackResult(False, "system_restore", "Restore point created.")
        return RollbackResult(True, "system_restore", f"CreateRestorePoint returned HRESULT {hresult}.")
    except pywintypes.com_error as e:
        return RollbackResult(True, "system_restore", f"COM error creating restore point: {e}")


def backup_file(path: str) -> RollbackResult:
    dest_dir = os.path.join(BACKUP_ROOT, time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, os.path.basename(path))
    try:
        shutil.copy2(path, dest)
        return RollbackResult(False, "file_backup", f"Backed up to {dest}", backup_path=dest)
    except OSError as e:
        return RollbackResult(True, "file_backup", f"Backup failed: {e}")


def create_rollback_point(spec, tool_input) -> RollbackResult:
    if "path" in tool_input:
        return backup_file(tool_input["path"])
    return create_system_restore_point(f"S.E.N.T.R.Y.: {spec.name}", spec.restore_point_type)
