"""Tests for the new AUTO-tier diagnostics: get_power_plan() and
get_windows_update_cache_size().

Everything here calls the REAL functions from diagnostics.py. subprocess.run
is monkeypatched wherever a real function would otherwise shell out to
powercfg — no live process is ever spawned, and no real filesystem outside
pytest's own tmp_path is ever touched.
"""
from types import SimpleNamespace

import pytest

import diagnostics
import safety


# ---------------------------------------------------------------------------
# get_power_plan — registration
# ---------------------------------------------------------------------------

def test_get_power_plan_registered_as_auto_tier_no_precheck():
    spec = safety.REGISTRY["get_power_plan"]
    assert spec.tier is safety.Tier.AUTO
    assert spec.is_action is False
    assert spec.precheck is None


def test_get_windows_update_cache_size_registered_as_auto_tier_no_precheck():
    spec = safety.REGISTRY["get_windows_update_cache_size"]
    assert spec.tier is safety.Tier.AUTO
    assert spec.is_action is False
    assert spec.precheck is None


# ---------------------------------------------------------------------------
# get_power_plan — parsing real 'powercfg /getactivescheme' output shape
# ---------------------------------------------------------------------------

def test_get_power_plan_parses_real_output_shape(monkeypatch):
    fake_stdout = "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)\r\n"
    monkeypatch.setattr(
        diagnostics.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=fake_stdout, stderr=""),
    )

    result = diagnostics.get_power_plan()

    assert result == {
        "guid": "381b4222-f694-41f0-9685-ff5bb260df2e",
        "name": "Balanced",
        "raw": fake_stdout.strip(),
    }


def test_get_power_plan_parses_high_performance(monkeypatch):
    fake_stdout = "Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)\r\n"
    monkeypatch.setattr(
        diagnostics.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=fake_stdout, stderr=""),
    )

    result = diagnostics.get_power_plan()

    assert result["guid"] == "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    assert result["name"] == "High performance"


def test_get_power_plan_unparsable_output_is_structured_error(monkeypatch):
    monkeypatch.setattr(
        diagnostics.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="nonsense output", stderr=""),
    )

    result = diagnostics.get_power_plan()

    assert result["error"] is True
    assert "Could not parse" in result["message"]


def test_get_power_plan_nonzero_exit_is_structured_error(monkeypatch):
    monkeypatch.setattr(
        diagnostics.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="access denied"),
    )

    result = diagnostics.get_power_plan()

    assert result["error"] is True
    assert "access denied" in result["message"]


def test_get_power_plan_command_not_found_is_structured_error(monkeypatch):
    def _raise(*a, **k):
        raise FileNotFoundError("powercfg not found")
    monkeypatch.setattr(diagnostics.subprocess, "run", _raise)

    result = diagnostics.get_power_plan()

    assert result["error"] is True
    assert "Failed to query" in result["message"]


def test_get_power_plan_timeout_is_structured_error(monkeypatch):
    import subprocess as real_subprocess

    def _raise(*a, **k):
        raise real_subprocess.TimeoutExpired(cmd="powercfg", timeout=15)
    monkeypatch.setattr(diagnostics.subprocess, "run", _raise)

    result = diagnostics.get_power_plan()

    assert result["error"] is True


# ---------------------------------------------------------------------------
# get_windows_update_cache_size — real _scan_dir over a fake %WINDIR%
# ---------------------------------------------------------------------------

def test_get_windows_update_cache_size_scans_real_directory(monkeypatch, tmp_path):
    windir = tmp_path / "Windows"
    download_dir = windir / "SoftwareDistribution" / "Download"
    download_dir.mkdir(parents=True)
    (download_dir / "a.cab").write_bytes(b"x" * 100)
    (download_dir / "b.cab").write_bytes(b"y" * 200)
    monkeypatch.setenv("WINDIR", str(windir))

    result = diagnostics.get_windows_update_cache_size()

    assert result["exists"] is True
    assert result["accessible"] is True
    assert result["file_count"] == 2
    assert result["path"] == str(download_dir)


def test_get_windows_update_cache_size_missing_directory_is_best_effort(monkeypatch, tmp_path):
    monkeypatch.setenv("WINDIR", str(tmp_path / "NoSuchWindows"))

    result = diagnostics.get_windows_update_cache_size()

    assert result["exists"] is False
    assert result["file_count"] == 0
    assert result["size_mb"] == 0.0
