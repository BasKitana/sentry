"""Tests for actions.py's hardened validation logic.

Everything here calls the REAL functions/constants from actions.py — no
reimplemented copies of the denylist or critical-process-name logic. No
live API calls, no real service restarts, no real registry writes, no real
process kills: psutil.Process, win32serviceutil.RestartService,
subprocess.Popen, rollback.create_rollback_point, and ui.confirm_action are
all mocked/faked via monkeypatch wherever a real function would otherwise
touch the OS.
"""
import os

import psutil
import pytest

import actions
import rollback
import safety
import ui


# ---------------------------------------------------------------------------
# _is_denylisted_path — bypass forms the Opus review found and fixed
# ---------------------------------------------------------------------------

def test_extended_length_prefix_path_is_denylisted():
    # "\\?\" local-device prefix must be stripped before comparison, not
    # treated as an opaque path that doesn't contain "Windows" literally.
    path = r"\\?\C:\Windows\System32\svchost.exe"
    assert actions._is_denylisted_path(path) is True


def test_extended_length_prefix_forward_slash_variant_is_denylisted():
    path = "//?/C:/Windows/System32/svchost.exe"
    assert actions._is_denylisted_path(path) is True


def test_unc_admin_share_path_is_denylisted():
    # A local admin share reaches System32 with no drive-letter prefix at
    # all, and must be refused outright rather than "normalized" away.
    path = r"\\localhost\C$\Windows\System32\drivers\etc\hosts"
    assert actions._is_denylisted_path(path) is True


def test_generic_unc_path_is_denylisted():
    path = r"\\fileserver\share\something.txt"
    assert actions._is_denylisted_path(path) is True


def test_8dot3_short_name_path_is_denylisted():
    # "C:\PROGRA~1" resolves to "C:\Program Files" via os.path.realpath;
    # WindowsApps under it is one of the whole-container "Program
    # Files\Windows*" targets that must not be reachable by spelling the
    # short name instead of the long one.
    path = r"C:\PROGRA~1\WindowsApps\foo.dll"
    assert actions._is_denylisted_path(path) is True


def test_bare_protected_root_program_files_is_denylisted():
    program_files = os.environ.get("PROGRAMFILES")
    if not program_files:
        pytest.skip("PROGRAMFILES not set in this environment")
    # The root itself, with nothing after it — a prefix check of the form
    # "starts with <dir>\" never matches <dir> itself, so this must be
    # covered by the explicit _protected_roots() membership check.
    assert actions._is_denylisted_path(program_files) is True


def test_bare_protected_root_users_is_denylisted():
    userprofile = os.environ.get("USERPROFILE")
    if not userprofile:
        pytest.skip("USERPROFILE not set in this environment")
    users_root = os.path.dirname(os.path.normpath(userprofile))
    assert actions._is_denylisted_path(users_root) is True


def test_bare_userprofile_root_is_denylisted():
    userprofile = os.environ.get("USERPROFILE")
    if not userprofile:
        pytest.skip("USERPROFILE not set in this environment")
    assert actions._is_denylisted_path(userprofile) is True


# ---------------------------------------------------------------------------
# _is_denylisted_path — no over-blocking regression
# ---------------------------------------------------------------------------

def test_tmp_path_fixture_location_is_not_denylisted(tmp_path):
    target = tmp_path / "somefile.txt"
    assert actions._is_denylisted_path(str(target)) is False


def test_real_user_documents_path_is_not_denylisted():
    userprofile = os.environ.get("USERPROFILE")
    if not userprofile:
        pytest.skip("USERPROFILE not set in this environment")
    target = os.path.join(userprofile, "Documents", "somefile.txt")
    assert actions._is_denylisted_path(target) is False


def test_file_inside_program_files_is_not_denylisted():
    # A legitimate target ("C:\Program Files\SomeApp\stale.log" in the
    # module's own docstring) must not be swept up by the whole-root rule.
    program_files = os.environ.get("PROGRAMFILES")
    if not program_files:
        pytest.skip("PROGRAMFILES not set in this environment")
    target = os.path.join(program_files, "SomeApp", "stale.log")
    assert actions._is_denylisted_path(target) is False


# ---------------------------------------------------------------------------
# Fakes for psutil.Process, used by the critical-process-denylist tests
# ---------------------------------------------------------------------------

class _FakeProc:
    """Stand-in for psutil.Process. Any method not configured to be used
    raises AssertionError if called, so tests can prove a code path never
    reached past the name-check guard."""

    def __init__(self, name_value=None, name_raises=None):
        self._name_value = name_value
        self._name_raises = name_raises

    def name(self):
        if self._name_raises is not None:
            raise self._name_raises
        return self._name_value

    def exe(self):
        raise AssertionError("proc.exe() should not have been called")

    def terminate(self):
        raise AssertionError("proc.terminate() should not have been called")

    def kill(self):
        raise AssertionError("proc.kill() should not have been called")

    def wait(self, timeout=None):
        raise AssertionError("proc.wait() should not have been called")


# ---------------------------------------------------------------------------
# _precheck_process — critical-process denylist, incl. the fail-open case
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("critical_name", sorted(actions._CRITICAL_PROCESS_NAMES))
def test_precheck_process_refuses_critical_names_case_insensitively(monkeypatch, critical_name):
    mixed_case = critical_name.swapcase()
    monkeypatch.setattr(psutil, "Process", lambda pid: _FakeProc(name_value=mixed_case))

    result = actions._precheck_process({"pid": 4242})

    assert result is not None
    assert result["error"] is True
    assert "critical OS process" in result["message"]


def test_precheck_process_allows_non_critical_name(monkeypatch):
    monkeypatch.setattr(psutil, "Process", lambda pid: _FakeProc(name_value="notepad.exe"))
    assert actions._precheck_process({"pid": 4242}) is None


def test_precheck_process_fails_open_refused_when_name_raises_access_denied(monkeypatch):
    # The fail-open bug: an unreadable process name previously behaved like
    # an empty/unmatched name (not in the denylist) and was allowed
    # through. psutil raises AccessDenied for exactly the protected
    # processes this guard exists to catch, so that must be a refusal.
    monkeypatch.setattr(
        psutil, "Process",
        lambda pid: _FakeProc(name_raises=psutil.AccessDenied(pid=pid, name=None)),
    )

    result = actions._precheck_process({"pid": 999})

    assert result is not None
    assert result["error"] is True
    assert "access denied" in result["message"].lower()


def test_precheck_process_no_such_process(monkeypatch):
    def _raise(pid):
        raise psutil.NoSuchProcess(pid=pid)
    monkeypatch.setattr(psutil, "Process", _raise)

    result = actions._precheck_process({"pid": 1})
    assert result is not None
    assert result["error"] is True


def test_precheck_process_no_pid_is_a_noop():
    assert actions._precheck_process({}) is None


# ---------------------------------------------------------------------------
# restart_unresponsive_process (AUTO tier) — same guard as kill_process,
# proven by calling the real function directly (it has no registered
# `precheck`, the guard lives inline in the function body).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("critical_name", sorted(actions._CRITICAL_PROCESS_NAMES))
def test_restart_unresponsive_process_refuses_critical_process(monkeypatch, critical_name):
    monkeypatch.setattr(psutil, "Process", lambda pid: _FakeProc(name_value=critical_name))

    def _no_popen(*a, **kw):
        raise AssertionError("subprocess.Popen should not have been called")
    monkeypatch.setattr(actions.subprocess, "Popen", _no_popen)

    result = actions.restart_unresponsive_process(pid=777)

    assert result["error"] is True
    assert "critical OS process" in result["message"]


def test_restart_unresponsive_process_fails_open_refused_on_access_denied(monkeypatch):
    monkeypatch.setattr(
        psutil, "Process",
        lambda pid: _FakeProc(name_raises=psutil.AccessDenied(pid=pid, name=None)),
    )

    def _no_popen(*a, **kw):
        raise AssertionError("subprocess.Popen should not have been called")
    monkeypatch.setattr(actions.subprocess, "Popen", _no_popen)

    result = actions.restart_unresponsive_process(pid=778)

    assert result["error"] is True
    assert "access denied" in result["message"].lower()


# ---------------------------------------------------------------------------
# restart_windows_service — exact allowlist
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_name", ["Themes", "BITS", "NotAService", "spooler", ""])
def test_restart_windows_service_refuses_names_off_allowlist(monkeypatch, bad_name):
    def _no_restart(name):
        raise AssertionError("win32serviceutil.RestartService should not have been called")
    monkeypatch.setattr(actions.win32serviceutil, "RestartService", _no_restart)

    result = actions.restart_windows_service(bad_name)

    assert result["error"] is True
    assert "allowlist" in result["message"]


@pytest.mark.parametrize("allowed_name", sorted(actions._SERVICE_ALLOWLIST))
def test_restart_windows_service_allows_exact_allowlist_entries(monkeypatch, allowed_name):
    calls = []
    monkeypatch.setattr(actions.win32serviceutil, "RestartService", lambda name: calls.append(name))

    result = actions.restart_windows_service(allowed_name)

    assert calls == [allowed_name]
    assert result.get("restarted") is True


# ---------------------------------------------------------------------------
# move_to_recycle_bin — registered tier must be APPROVAL, not AUTO
# ---------------------------------------------------------------------------

def test_move_to_recycle_bin_is_registered_as_approval_tier():
    spec = safety.REGISTRY["move_to_recycle_bin"]
    assert spec.tier is safety.Tier.APPROVAL


# ---------------------------------------------------------------------------
# Not-implemented stubs: refuse before any rollback point is attempted
# ---------------------------------------------------------------------------

def _raise_if_rollback_attempted(*args, **kwargs):
    raise AssertionError(
        "rollback.create_rollback_point should never be reached for a "
        "not-implemented stub — its precheck must refuse first."
    )


def _raise_if_confirm_attempted(*args, **kwargs):
    raise AssertionError(
        "ui.confirm_action should never be reached for a not-implemented "
        "stub — its precheck must refuse before the approval prompt."
    )


@pytest.mark.parametrize(
    "tool_name, tool_input, func",
    [
        ("install_software", {"name": "Some App"}, actions.install_software),
        ("uninstall_software", {"name": "Some App"}, actions.uninstall_software),
        ("rollback_driver", {"device": "Some Driver"}, actions.rollback_driver),
    ],
)
def test_not_implemented_stub_function_returns_not_implemented(tool_name, tool_input, func):
    result = func(**tool_input)
    assert result == actions._NOT_IMPLEMENTED
    # Must be a fresh copy, not the shared module-level dict, so a caller
    # mutating the result can't corrupt the constant for later calls.
    assert result is not actions._NOT_IMPLEMENTED


@pytest.mark.parametrize(
    "tool_name, tool_input",
    [
        ("install_software", {"name": "Some App"}),
        ("uninstall_software", {"name": "Some App"}),
        ("rollback_driver", {"device": "Some Driver"}),
    ],
)
def test_not_implemented_stub_precheck_refuses_before_rollback_point(monkeypatch, tool_name, tool_input):
    monkeypatch.setattr(rollback, "create_rollback_point", _raise_if_rollback_attempted)
    monkeypatch.setattr(ui, "confirm_action", _raise_if_confirm_attempted)

    result, resolved = safety.dispatch(tool_name, tool_input)

    assert result == actions._NOT_IMPLEMENTED
    assert resolved is True
