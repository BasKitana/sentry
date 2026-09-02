"""Tests for rollback.py — System Restore point creation and file backup.

win32com.client / pywintypes are monkeypatched so nothing here ever touches
real Windows state (no real System Restore point is created). backup_file is
pointed at a pytest tmp_path via rollback.BACKUP_ROOT so nothing is written
outside pytest's own temp directory, and no real deletion of any kind happens
anywhere in this file.
"""
from pathlib import Path

import pytest
import pywintypes

import rollback


# ---------------------------------------------------------------------------
# create_system_restore_point
# ---------------------------------------------------------------------------

def test_create_system_restore_point_success(monkeypatch):
    calls = []

    class FakeSystemRestore:
        def CreateRestorePoint(self, description, restore_point_type, event_type):
            calls.append((description, restore_point_type, event_type))
            return 0  # HRESULT 0 == success

    monkeypatch.setattr(
        rollback.win32com.client, "GetObject", lambda moniker: FakeSystemRestore()
    )

    result = rollback.create_system_restore_point("S.E.N.T.R.Y.: test action", 12)

    assert result.failed is False
    assert result.method == "system_restore"
    assert "created" in result.detail.lower()
    assert calls == [("S.E.N.T.R.Y.: test action", 12, 100)]


def test_create_system_restore_point_nonzero_hresult_is_a_failure(monkeypatch):
    class FakeSystemRestore:
        def CreateRestorePoint(self, description, restore_point_type, event_type):
            return 1  # e.g. throttled to ~1/24h, or otherwise refused

    monkeypatch.setattr(
        rollback.win32com.client, "GetObject", lambda moniker: FakeSystemRestore()
    )

    result = rollback.create_system_restore_point("S.E.N.T.R.Y.: test action", 12)

    assert result.failed is True
    assert result.method == "system_restore"
    assert "1" in result.detail


def test_create_system_restore_point_com_error_is_caught_not_propagated(monkeypatch):
    def raise_com_error(moniker):
        raise pywintypes.com_error(-2147352567, "Exception occurred.", None, None)

    monkeypatch.setattr(rollback.win32com.client, "GetObject", raise_com_error)

    # Must not raise — the whole point is that this is caught and converted.
    result = rollback.create_system_restore_point("S.E.N.T.R.Y.: test action", 12)

    assert result.failed is True
    assert result.method == "system_restore"
    assert "COM error" in result.detail


# ---------------------------------------------------------------------------
# backup_file
# ---------------------------------------------------------------------------

def test_backup_file_success_copy_lands_under_fake_backup_root(monkeypatch, tmp_path):
    fake_backup_root = tmp_path / "backups"
    monkeypatch.setattr(rollback, "BACKUP_ROOT", str(fake_backup_root))

    src = tmp_path / "source.txt"
    src.write_text("hello world", encoding="utf-8")

    result = rollback.backup_file(str(src))

    assert result.failed is False
    assert result.method == "file_backup"
    assert result.backup_path is not None

    backup_path = Path(result.backup_path)
    assert backup_path.exists()
    assert backup_path.read_text(encoding="utf-8") == "hello world"
    assert backup_path.is_relative_to(fake_backup_root)
    # original file must be untouched (this is a copy, not a move)
    assert src.exists()


def test_backup_file_failure_oserror_caught_not_propagated(monkeypatch, tmp_path):
    fake_backup_root = tmp_path / "backups"
    monkeypatch.setattr(rollback, "BACKUP_ROOT", str(fake_backup_root))

    missing_src = tmp_path / "does_not_exist.txt"  # never created

    # Must not raise — the whole point is that OSError is caught.
    result = rollback.backup_file(str(missing_src))

    assert result.failed is True
    assert result.method == "file_backup"
    assert result.backup_path is None
    assert "Backup failed" in result.detail


# ---------------------------------------------------------------------------
# create_rollback_point routing
# ---------------------------------------------------------------------------

class _FakeSpec:
    def __init__(self, name="some_tool", restore_point_type=12):
        self.name = name
        self.restore_point_type = restore_point_type


def _raise(*_a, **_k):
    raise AssertionError("this should never have been called")


def test_create_rollback_point_routes_to_backup_file_when_path_present(monkeypatch):
    calls = []

    def fake_backup_file(path):
        calls.append(("backup_file", path))
        return rollback.RollbackResult(False, "file_backup", "ok", backup_path="fake")

    monkeypatch.setattr(rollback, "backup_file", fake_backup_file)
    monkeypatch.setattr(rollback, "create_system_restore_point", _raise)

    result = rollback.create_rollback_point(_FakeSpec(), {"path": "C:\\some\\file.txt"})

    assert calls == [("backup_file", "C:\\some\\file.txt")]
    assert result.method == "file_backup"


def test_create_rollback_point_routes_to_system_restore_when_no_path(monkeypatch):
    calls = []

    def fake_create_system_restore_point(description, restore_point_type):
        calls.append((description, restore_point_type))
        return rollback.RollbackResult(False, "system_restore", "ok")

    monkeypatch.setattr(rollback, "backup_file", _raise)
    monkeypatch.setattr(rollback, "create_system_restore_point", fake_create_system_restore_point)

    result = rollback.create_rollback_point(_FakeSpec(name="kill_process", restore_point_type=12), {"pid": 4242})

    assert calls == [("S.E.N.T.R.Y.: kill_process", 12)]
    assert result.method == "system_restore"
