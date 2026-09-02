"""AUTO-tier, read-only diagnostic tools.

Refactor of the old main.py psutil logic (get_cpu_percentage, get_memory,
get_disk) plus new diagnostics the MVP scenarios need. Every function here
returns a structured dict (never a formatted display string) and is
registered as an AUTO, non-action tool — nothing in this module has a side
effect on the system.
"""

import os
import time

import psutil
import pywintypes
import win32com.client

import safety
from safety import Tier


@safety.register_tool(
    name="get_cpu_usage",
    description="Get current CPU utilization. Call when the user reports the system feels slow or unresponsive.",
    input_schema={"type": "object", "properties": {}, "required": []},
    tier=Tier.AUTO,
    is_action=False,
)
def get_cpu_usage() -> dict:
    percent = psutil.cpu_percent(interval=0.5)
    return {
        "percent": percent,
        "core_count_logical": psutil.cpu_count(logical=True),
        "core_count_physical": psutil.cpu_count(logical=False),
    }


@safety.register_tool(
    name="get_memory_usage",
    description="Get current RAM usage. Call when the user reports the system feels slow, laggy, or programs are crashing due to low memory.",
    input_schema={"type": "object", "properties": {}, "required": []},
    tier=Tier.AUTO,
    is_action=False,
)
def get_memory_usage() -> dict:
    m = psutil.virtual_memory()
    return {
        "total_gb": round(m.total / 2**30, 2),
        "available_gb": round(m.available / 2**30, 2),
        "used_gb": round(m.used / 2**30, 2),
        "percent": m.percent,
    }


@safety.register_tool(
    name="get_disk_usage",
    description="Get disk space usage for a drive. Call when the user mentions low disk space.",
    input_schema={"type": "object", "properties": {
        "drive": {"type": "string", "description": "Drive letter, e.g. 'C:\\\\'. Defaults to C:\\\\."}
    }, "required": []},
    tier=Tier.AUTO,
    is_action=False,
)
def get_disk_usage(drive: str = "C:\\") -> dict:
    d = psutil.disk_usage(drive)
    return {"drive": drive, "total_gb": round(d.total / 2**30, 2),
            "free_gb": round(d.free / 2**30, 2), "percent": d.percent}


@safety.register_tool(
    name="list_processes",
    description="List running processes sorted by CPU or memory usage. Call when the user reports the system is slow and you need to identify which process is responsible.",
    input_schema={"type": "object", "properties": {
        "sort_by": {"type": "string", "enum": ["cpu", "memory"],
                    "description": "Sort processes by 'cpu' or 'memory' usage. Defaults to 'cpu'."},
        "limit": {"type": "integer", "description": "Maximum number of processes to return. Defaults to 15."}
    }, "required": []},
    tier=Tier.AUTO,
    is_action=False,
)
def list_processes(sort_by: str = "cpu", limit: int = 15) -> dict:
    sort_by = sort_by if sort_by in ("cpu", "memory") else "cpu"
    limit = limit if isinstance(limit, int) and limit > 0 else 15

    procs = list(psutil.process_iter(["pid", "name", "username"]))
    # First cpu_percent() call on a process always returns 0.0 (it needs a
    # time delta to measure against) — prime every process, wait briefly,
    # then read real values below.
    for p in procs:
        try:
            p.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    time.sleep(0.2)

    results = []
    for p in procs:
        try:
            with p.oneshot():
                cpu = p.cpu_percent(interval=None)
                mem_mb = round(p.memory_info().rss / 2**20, 2)
                info = p.info
            results.append({
                "pid": info.get("pid"),
                "name": info.get("name"),
                "username": info.get("username"),
                "cpu_percent": cpu,
                "memory_mb": mem_mb,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    key = "cpu_percent" if sort_by == "cpu" else "memory_mb"
    results.sort(key=lambda r: r[key], reverse=True)
    trimmed = results[:limit]
    return {"sort_by": sort_by, "count": len(trimmed), "processes": trimmed}


@safety.register_tool(
    name="list_startup_items",
    description="List programs configured to launch automatically when Windows starts, via the documented Win32_StartupCommand WMI class. Call when the user asks what launches at startup or whether any startup program looks suspicious.",
    input_schema={"type": "object", "properties": {}, "required": []},
    tier=Tier.AUTO,
    is_action=False,
)
def list_startup_items() -> dict:
    items = []
    try:
        wmi = win32com.client.GetObject("winmgmts:")
        for item in wmi.ExecQuery(
            "SELECT Name, Command, Location, User FROM Win32_StartupCommand"
        ):
            items.append({
                "name": getattr(item, "Name", None),
                "command": getattr(item, "Command", None),
                "location": getattr(item, "Location", None),
                "user": getattr(item, "User", None),
            })
    except pywintypes.com_error as e:
        return {"error": True, "message": f"COM error querying startup items: {e}", "items": []}

    return {"count": len(items), "items": items}


def _scan_dir(path: str) -> dict:
    """Best-effort size/count of a directory. Never raises."""
    if not path:
        return {"path": path, "exists": False, "accessible": False, "file_count": 0, "size_mb": 0.0}
    try:
        if not os.path.isdir(path):
            return {"path": path, "exists": False, "accessible": False, "file_count": 0, "size_mb": 0.0}
    except (OSError, PermissionError):
        return {"path": path, "exists": False, "accessible": False, "file_count": 0, "size_mb": 0.0}

    total_size = 0
    file_count = 0
    skipped = 0
    accessible = True
    try:
        for root, dirs, files in os.walk(path, onerror=lambda e: None):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    total_size += os.path.getsize(fpath)
                    file_count += 1
                except (OSError, PermissionError):
                    skipped += 1
                    continue
    except PermissionError:
        accessible = False

    return {
        "path": path,
        "exists": True,
        "accessible": accessible,
        "file_count": file_count,
        "skipped_files": skipped,
        "size_mb": round(total_size / 2**20, 2),
    }


@safety.register_tool(
    name="get_temp_file_info",
    description="Report the size and file count of temp directories (%TEMP% and, best-effort, C:\\Windows\\Temp). Call when the user mentions low disk space, to see whether clearing temp files would help.",
    input_schema={"type": "object", "properties": {}, "required": []},
    tier=Tier.AUTO,
    is_action=False,
)
def get_temp_file_info() -> dict:
    user_temp = os.environ.get("TEMP") or os.environ.get("TMP")
    windows_temp = r"C:\Windows\Temp"

    locations = {
        "user_temp": _scan_dir(user_temp),
        "windows_temp": _scan_dir(windows_temp),
    }

    total_size_mb = round(sum(loc["size_mb"] for loc in locations.values()), 2)
    total_file_count = sum(loc["file_count"] for loc in locations.values())

    return {
        "locations": locations,
        "total_size_mb": total_size_mb,
        "total_file_count": total_file_count,
    }
