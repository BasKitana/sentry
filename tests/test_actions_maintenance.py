"""Tests for the new APPROVAL-tier maintenance tools in actions.py:
set_power_plan, set_visual_effects_for_performance, optimize_drive,
clear_windows_update_cache, run_component_cleanup.

Everything here calls the REAL functions/constants from actions.py — no
reimplemented copies of the power-plan allowlist or drive-validation logic.
No live API calls, no real service restarts, no real registry writes, no
real subprocess ever runs: subprocess.run, win32serviceutil.StopService/
StartService, winreg.*, psutil.disk_partitions, rollback.create_rollback_point
and ui.confirm_action are all mocked/faked via monkeypatch wherever a real
call would otherwise touch the OS.
"""
from collections import namedtuple
from types import SimpleNamespace

import pytest

import actions
import rollback
import safety
import ui


def _raise_if_rollback_attempted(*args, **kwargs):
    raise AssertionError(
        "rollback.create_rollback_point should never be reached — the "
        "precheck must refuse first."
    )


def _raise_if_confirm_attempted(*args, **kwargs):
    raise AssertionError(
        "ui.confirm_action should never be reached — the precheck must "
        "refuse before the approval prompt."
    )


# ---------------------------------------------------------------------------
# Registration — all five are APPROVAL tier
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "set_power_plan",
    "set_visual_effects_for_performance",
    "optimize_drive",
    "clear_windows_update_cache",
    "run_component_cleanup",
])
def test_new_maintenance_tools_registered_as_approval_tier(name):
    assert safety.REGISTRY[name].tier is safety.Tier.APPROVAL
    assert safety.REGISTRY[name].is_action is True


@pytest.mark.parametrize("name", ["set_power_plan", "optimize_drive"])
def test_free_form_parameter_tools_have_a_precheck(name):
    assert safety.REGISTRY[name].precheck is not None


@pytest.mark.parametrize("name", [
    "set_visual_effects_for_performance", "clear_windows_update_cache", "run_component_cleanup",
])
def test_no_free_form_parameter_tools_have_no_precheck(name):
    assert safety.REGISTRY[name].precheck is None


# ---------------------------------------------------------------------------
# set_power_plan — fixed allowlist, real GUIDs
# ---------------------------------------------------------------------------

def test_power_plan_guids_are_the_verified_well_known_values():
    # Verified against Microsoft's own powercfg command-line-options
    # documentation (which uses the Balanced GUID in its own worked
    # examples) and cross-checked across independent sources for the other
    # two. A change here changes which real Windows power plan gets
    # activated, so this is pinned explicitly rather than left implicit.
    assert actions._POWER_PLAN_GUIDS == {
        "high_performance": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
        "balanced": "381b4222-f694-41f0-9685-ff5bb260df2e",
        "power_saver": "a1841308-3541-4fab-bc81-f71556f20b4a",
    }


@pytest.mark.parametrize("plan", sorted(actions._POWER_PLAN_GUIDS))
def test_precheck_power_plan_allows_allowlisted_plans(plan):
    assert actions._precheck_power_plan({"plan": plan}) is None


@pytest.mark.parametrize("bad_plan", ["ultra_performance", "HIGH_PERFORMANCE", "", None, 123, "balanced "])
def test_precheck_power_plan_rejects_anything_off_allowlist(bad_plan):
    result = actions._precheck_power_plan({"plan": bad_plan})
    assert result is not None
    assert result["error"] is True
    assert "allowlist" in result["message"]


def test_set_power_plan_rejects_invalid_plan_without_touching_subprocess(monkeypatch):
    def _no_run(*a, **k):
        raise AssertionError("subprocess.run should not have been called")
    monkeypatch.setattr(actions.subprocess, "run", _no_run)

    result = actions.set_power_plan("ultra_turbo")

    assert result["error"] is True
    assert "allowlist" in result["message"]


def test_set_power_plan_precheck_refuses_before_confirm_and_rollback(monkeypatch):
    monkeypatch.setattr(rollback, "create_rollback_point", _raise_if_rollback_attempted)
    monkeypatch.setattr(ui, "confirm_action", _raise_if_confirm_attempted)

    result, resolved = safety.dispatch("set_power_plan", {"plan": "not_a_real_plan"})

    assert result["error"] is True
    assert "allowlist" in result["message"]
    assert resolved is True


def test_set_power_plan_success_shape(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(actions.subprocess, "run", fake_run)
    monkeypatch.setattr(actions.diagnostics, "get_power_plan",
                         lambda: {"guid": "fake", "name": "Fake"})

    result = actions.set_power_plan("balanced")

    assert calls == [["powercfg", "/setactive", actions._POWER_PLAN_GUIDS["balanced"]]]
    assert result["changed"] is True
    assert result["plan"] == "balanced"
    assert result["guid"] == actions._POWER_PLAN_GUIDS["balanced"]
    assert result["before"] == {"guid": "fake", "name": "Fake"}
    assert result["after"] == {"guid": "fake", "name": "Fake"}
    assert result.get("error") is not True


def test_set_power_plan_nonzero_exit_is_structured_error(monkeypatch):
    monkeypatch.setattr(
        actions.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="powercfg failed"),
    )
    monkeypatch.setattr(actions.diagnostics, "get_power_plan", lambda: {})

    result = actions.set_power_plan("power_saver")

    assert result["error"] is True
    assert "powercfg failed" in result["message"]


def test_set_power_plan_command_not_found_is_structured_error(monkeypatch):
    def _raise(*a, **k):
        raise FileNotFoundError("powercfg not found")
    monkeypatch.setattr(actions.subprocess, "run", _raise)

    result = actions.set_power_plan("high_performance")

    assert result["error"] is True
    assert "Failed to switch power plan" in result["message"]


# ---------------------------------------------------------------------------
# optimize_drive — precheck rejects non-real/network/removable drives
# ---------------------------------------------------------------------------

_FakePart = namedtuple("_FakePart", ["device", "mountpoint", "fstype", "opts"])

_FAKE_PARTITIONS = [
    _FakePart("C:\\", "C:\\", "NTFS", "rw,fixed"),
    _FakePart("D:\\", "D:\\", "", "cdrom"),
    _FakePart("Z:\\", "Z:\\", "NTFS", "rw,remote"),
    _FakePart("E:\\", "E:\\", "FAT32", "rw,removable"),
]


def _patch_partitions(monkeypatch):
    monkeypatch.setattr(actions.psutil, "disk_partitions", lambda all=False: list(_FAKE_PARTITIONS))


def test_find_fixed_drive_matches_the_real_fixed_drive(monkeypatch):
    _patch_partitions(monkeypatch)
    assert actions._find_fixed_drive("C:") is not None
    assert actions._find_fixed_drive("c:\\") is not None
    assert actions._find_fixed_drive("c") is not None


@pytest.mark.parametrize("bad_drive", ["Z:", "D:", "E:", "Q:", "not-a-drive", "", None])
def test_find_fixed_drive_rejects_everything_else(monkeypatch, bad_drive):
    _patch_partitions(monkeypatch)
    assert actions._find_fixed_drive(bad_drive) is None


def test_precheck_drive_allows_real_fixed_drive(monkeypatch):
    _patch_partitions(monkeypatch)
    assert actions._precheck_drive({"drive": "C:"}) is None


@pytest.mark.parametrize("bad_drive", ["Z:", "D:", "E:", "Q:", "\\\\server\\share"])
def test_precheck_drive_rejects_network_removable_optical_and_unmounted(monkeypatch, bad_drive):
    _patch_partitions(monkeypatch)
    result = actions._precheck_drive({"drive": bad_drive})
    assert result is not None
    assert result["error"] is True
    assert "not a currently-mounted local fixed drive" in result["message"]


@pytest.mark.parametrize("missing", [{}, {"drive": ""}, {"drive": 123}, {"drive": None}])
def test_precheck_drive_rejects_missing_or_non_string_drive(missing):
    result = actions._precheck_drive(missing)
    assert result is not None
    assert result["error"] is True


def test_optimize_drive_precheck_refuses_before_confirm_and_rollback(monkeypatch):
    _patch_partitions(monkeypatch)
    monkeypatch.setattr(rollback, "create_rollback_point", _raise_if_rollback_attempted)
    monkeypatch.setattr(ui, "confirm_action", _raise_if_confirm_attempted)

    result, resolved = safety.dispatch("optimize_drive", {"drive": "Z:"})

    assert result["error"] is True
    assert resolved is True


def test_optimize_drive_rejects_network_drive_without_touching_subprocess(monkeypatch):
    _patch_partitions(monkeypatch)

    def _no_run(*a, **k):
        raise AssertionError("subprocess.run should not have been called")
    monkeypatch.setattr(actions.subprocess, "run", _no_run)

    result = actions.optimize_drive("Z:")

    assert result["error"] is True


def test_optimize_drive_success_shape(monkeypatch):
    _patch_partitions(monkeypatch)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="The operation completed successfully.", stderr="")
    monkeypatch.setattr(actions.subprocess, "run", fake_run)

    result = actions.optimize_drive("c:")

    assert calls == [["defrag", "C:", "/O"]]
    assert result["optimized"] is True
    assert result["drive"] == "C:"
    assert result.get("error") is not True


def test_optimize_drive_nonzero_exit_is_structured_error(monkeypatch):
    _patch_partitions(monkeypatch)
    monkeypatch.setattr(
        actions.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="defrag failed"),
    )

    result = actions.optimize_drive("C:")

    assert result["error"] is True
    assert "defrag failed" in result["message"]


# ---------------------------------------------------------------------------
# set_visual_effects_for_performance — VisualFXSetting registry writes,
# preserve-original-then-verify-readback
# ---------------------------------------------------------------------------

def _install_fake_winreg(monkeypatch, initial_value=None, fail_open=False, fail_write=False,
                          corrupt_readback=False):
    state = {"values": {}, "written": False, "flushed": False, "closed": False}
    if initial_value is not None:
        state["values"][actions._VISUAL_FX_SETTING_NAME] = initial_value

    class _FakeKey:
        pass

    def fake_create_key_ex(hive, subkey, res, access):
        if fail_open:
            raise OSError("cannot open/create VisualEffects key")
        assert hive == actions.winreg.HKEY_CURRENT_USER
        assert subkey == actions._VISUAL_EFFECTS_KEY
        return _FakeKey()

    def fake_query_value_ex(key, name):
        if corrupt_readback and state["written"]:
            return (999, actions.winreg.REG_DWORD)
        if name in state["values"]:
            return (state["values"][name], actions.winreg.REG_DWORD)
        raise FileNotFoundError()

    def fake_set_value_ex(key, name, res, type_, value):
        if fail_write:
            raise OSError("cannot write VisualFXSetting")
        state["values"][name] = value
        state["written"] = True

    def fake_flush_key(key):
        state["flushed"] = True

    def fake_close_key(key):
        state["closed"] = True

    monkeypatch.setattr(actions.winreg, "CreateKeyEx", fake_create_key_ex)
    monkeypatch.setattr(actions.winreg, "QueryValueEx", fake_query_value_ex)
    monkeypatch.setattr(actions.winreg, "SetValueEx", fake_set_value_ex)
    monkeypatch.setattr(actions.winreg, "FlushKey", fake_flush_key)
    monkeypatch.setattr(actions.winreg, "CloseKey", fake_close_key)
    return state


def test_set_visual_effects_enabled_true_writes_best_performance(monkeypatch, tmp_path):
    monkeypatch.setattr(rollback, "BACKUP_ROOT", str(tmp_path / "backups"))
    state = _install_fake_winreg(monkeypatch)

    result = actions.set_visual_effects_for_performance(True)

    assert result["changed"] is True
    assert result["confirmed"] is True
    assert result["enabled"] is True
    assert state["values"][actions._VISUAL_FX_SETTING_NAME] == actions._VISUAL_FX_BEST_PERFORMANCE
    assert state["flushed"] is True
    assert state["closed"] is True
    assert result["backup"]["backed_up"] is True


def test_set_visual_effects_enabled_false_restores_windows_default(monkeypatch, tmp_path):
    monkeypatch.setattr(rollback, "BACKUP_ROOT", str(tmp_path / "backups"))
    state = _install_fake_winreg(monkeypatch, initial_value=actions._VISUAL_FX_BEST_PERFORMANCE)

    result = actions.set_visual_effects_for_performance(False)

    assert result["changed"] is True
    assert result["before"] == actions._VISUAL_FX_BEST_PERFORMANCE
    assert state["values"][actions._VISUAL_FX_SETTING_NAME] == actions._VISUAL_FX_LET_WINDOWS_CHOOSE


def test_set_visual_effects_key_open_failure_is_structured_error(monkeypatch, tmp_path):
    monkeypatch.setattr(rollback, "BACKUP_ROOT", str(tmp_path / "backups"))
    _install_fake_winreg(monkeypatch, fail_open=True)

    result = actions.set_visual_effects_for_performance(True)

    assert result["error"] is True
    assert "VisualEffects" in result["message"]


def test_set_visual_effects_write_failure_is_structured_error_with_backup_info(monkeypatch, tmp_path):
    monkeypatch.setattr(rollback, "BACKUP_ROOT", str(tmp_path / "backups"))
    _install_fake_winreg(monkeypatch, fail_write=True)

    result = actions.set_visual_effects_for_performance(True)

    assert result["error"] is True
    assert "backup" in result


def test_set_visual_effects_readback_mismatch_is_flagged_not_confirmed(monkeypatch, tmp_path):
    monkeypatch.setattr(rollback, "BACKUP_ROOT", str(tmp_path / "backups"))
    _install_fake_winreg(monkeypatch, corrupt_readback=True)

    result = actions.set_visual_effects_for_performance(True)

    assert result["changed"] is True
    assert result["confirmed"] is False
    assert "did not match" in result["message"]


# ---------------------------------------------------------------------------
# clear_windows_update_cache — structured success/error, no real service
# restart, no real deletion outside tmp_path
# ---------------------------------------------------------------------------

def test_clear_windows_update_cache_success_shape(monkeypatch, tmp_path):
    windir = tmp_path / "Windows"
    download_dir = windir / "SoftwareDistribution" / "Download"
    download_dir.mkdir(parents=True)
    (download_dir / "update1.cab").write_bytes(b"x" * 1024)
    sub = download_dir / "sub"
    sub.mkdir()
    (sub / "update2.cab").write_bytes(b"y" * 2048)
    monkeypatch.setenv("WINDIR", str(windir))

    stop_calls, start_calls = [], []
    monkeypatch.setattr(actions.win32serviceutil, "StopService", lambda name: stop_calls.append(name))
    monkeypatch.setattr(actions.win32serviceutil, "StartService", lambda name: start_calls.append(name))

    result = actions.clear_windows_update_cache()

    assert stop_calls == ["wuauserv"]
    assert start_calls == ["wuauserv"]
    assert result["cleared"] is True
    assert result["items_deleted"] == 2
    assert result["items_skipped"] == 0
    assert result["service_restarted"] is True
    assert result.get("error") is not True
    assert download_dir.exists()
    assert list(download_dir.iterdir()) == []


def test_clear_windows_update_cache_stop_failure_short_circuits(monkeypatch, tmp_path):
    monkeypatch.setenv("WINDIR", str(tmp_path))

    def _raise_stop(name):
        raise RuntimeError("Access is denied.")
    monkeypatch.setattr(actions.win32serviceutil, "StopService", _raise_stop)

    def _no_start(name):
        raise AssertionError("StartService should not have been called after a stop failure")
    monkeypatch.setattr(actions.win32serviceutil, "StartService", _no_start)

    result = actions.clear_windows_update_cache()

    assert result["error"] is True
    assert "wuauserv" in result["message"]


def test_clear_windows_update_cache_missing_download_dir_still_restarts_service(monkeypatch, tmp_path):
    monkeypatch.setenv("WINDIR", str(tmp_path / "NoSuchWindows"))
    stop_calls, start_calls = [], []
    monkeypatch.setattr(actions.win32serviceutil, "StopService", lambda name: stop_calls.append(name))
    monkeypatch.setattr(actions.win32serviceutil, "StartService", lambda name: start_calls.append(name))

    result = actions.clear_windows_update_cache()

    assert stop_calls == ["wuauserv"]
    assert start_calls == ["wuauserv"]
    assert result["items_deleted"] == 0
    assert "scan_error" in result


def test_clear_windows_update_cache_restart_failure_flags_error(monkeypatch, tmp_path):
    windir = tmp_path / "Windows"
    (windir / "SoftwareDistribution" / "Download").mkdir(parents=True)
    monkeypatch.setenv("WINDIR", str(windir))
    monkeypatch.setattr(actions.win32serviceutil, "StopService", lambda name: None)

    def _raise_start(name):
        raise RuntimeError("service failed to start")
    monkeypatch.setattr(actions.win32serviceutil, "StartService", _raise_start)

    result = actions.clear_windows_update_cache()

    assert result.get("error") is True
    assert result["service_restarted"] is False


# ---------------------------------------------------------------------------
# run_component_cleanup — structured success/error
# ---------------------------------------------------------------------------

def test_run_component_cleanup_success_shape(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="The operation completed successfully.", stderr="")
    monkeypatch.setattr(actions.subprocess, "run", fake_run)

    result = actions.run_component_cleanup()

    assert calls == [["Dism.exe", "/online", "/Cleanup-Image", "/StartComponentCleanup"]]
    assert result["cleaned_up"] is True
    assert result.get("error") is not True


def test_run_component_cleanup_nonzero_exit_is_structured_error(monkeypatch):
    monkeypatch.setattr(
        actions.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=87, stdout="", stderr="Error: 87"),
    )

    result = actions.run_component_cleanup()

    assert result["error"] is True
    assert "87" in result["message"]


def test_run_component_cleanup_command_not_found_is_structured_error(monkeypatch):
    def _raise(*a, **k):
        raise FileNotFoundError("Dism.exe not found")
    monkeypatch.setattr(actions.subprocess, "run", _raise)

    result = actions.run_component_cleanup()

    assert result["error"] is True
    assert "Failed to run DISM component cleanup" in result["message"]


def test_run_component_cleanup_timeout_is_structured_error(monkeypatch):
    import subprocess as real_subprocess

    def _raise(*a, **k):
        raise real_subprocess.TimeoutExpired(cmd="Dism.exe", timeout=1800)
    monkeypatch.setattr(actions.subprocess, "run", _raise)

    result = actions.run_component_cleanup()

    assert result["error"] is True
