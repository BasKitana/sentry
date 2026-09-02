"""Tests for safety.py — the tool-dispatch gate.

Everything here calls the REAL safety.dispatch() / safety.register_tool() /
safety.register_blocked(). Nothing is reimplemented. Each test gets a fresh,
empty safety.REGISTRY (via the autouse `fresh_registry` fixture below) so
tests can register their own fake tools without colliding with each other or
with the real diagnostics/actions/blocked tool set, and can run in any order.

ui.confirm_action / ui.confirm_without_rollback and rollback.create_rollback_point
are monkeypatched per-test; rollback.py's own internals are never touched here
(see test_rollback.py for that).
"""
import pytest

import safety
import rollback
import ui
from safety import Tier, ToolSpec


EMPTY_SCHEMA = {"type": "object", "properties": {}, "required": []}


def _raise(*_a, **_k):
    raise AssertionError("this should never have been called")


@pytest.fixture(autouse=True)
def fresh_registry(monkeypatch):
    """Give every test an empty, isolated safety.REGISTRY.

    register_tool()/register_blocked()/dispatch() all read/write the module
    global named REGISTRY inside safety.py's own namespace, so rebinding the
    module attribute here (not a copy) is enough for the real functions to
    see the fresh dict.
    """
    monkeypatch.setattr(safety, "REGISTRY", {})
    yield


# ---------------------------------------------------------------------------
# AUTO tier
# ---------------------------------------------------------------------------

def test_auto_tier_runs_immediately_with_no_confirmation(monkeypatch):
    calls = []
    monkeypatch.setattr(ui, "confirm_action", _raise)
    monkeypatch.setattr(ui, "confirm_without_rollback", _raise)
    monkeypatch.setattr(rollback, "create_rollback_point", _raise)

    @safety.register_tool(
        name="auto_tool", description="d", input_schema=EMPTY_SCHEMA, tier=Tier.AUTO,
    )
    def auto_tool():
        calls.append("ran")
        return {"ok": True}

    result, is_action = safety.dispatch("auto_tool", {})

    assert calls == ["ran"]
    assert result == {"ok": True}
    assert is_action is False  # register_tool's default is_action=False


# ---------------------------------------------------------------------------
# APPROVAL tier
# ---------------------------------------------------------------------------

def _register_approval_tool(calls):
    @safety.register_tool(
        name="approval_tool", description="d", input_schema=EMPTY_SCHEMA, tier=Tier.APPROVAL,
    )
    def approval_tool():
        calls.append("ran")
        return {"ok": True}
    return approval_tool


def test_approval_tier_decline_func_never_called(monkeypatch):
    calls = []
    _register_approval_tool(calls)

    monkeypatch.setattr(ui, "confirm_action", lambda spec, tool_input: False)
    monkeypatch.setattr(ui, "confirm_without_rollback", _raise)
    monkeypatch.setattr(rollback, "create_rollback_point", _raise)

    result, is_action = safety.dispatch("approval_tool", {})

    assert calls == []
    assert result == {"declined": True, "message": "User declined. No changes made."}
    assert is_action is True


def test_approval_tier_approve_rollback_succeeds_func_called_rollback_attached(monkeypatch):
    calls = []
    _register_approval_tool(calls)

    monkeypatch.setattr(ui, "confirm_action", lambda spec, tool_input: True)
    monkeypatch.setattr(ui, "confirm_without_rollback", _raise)
    fake_rb = rollback.RollbackResult(False, "system_restore", "Restore point created.")
    monkeypatch.setattr(rollback, "create_rollback_point", lambda spec, tool_input: fake_rb)

    result, is_action = safety.dispatch("approval_tool", {})

    assert calls == ["ran"]
    assert result["ok"] is True
    assert result["rollback"] == {"method": "system_restore", "detail": "Restore point created."}
    assert is_action is True


def test_approval_tier_rollback_fails_user_declines_fallback_func_never_called(monkeypatch):
    calls = []
    _register_approval_tool(calls)

    monkeypatch.setattr(ui, "confirm_action", lambda spec, tool_input: True)
    monkeypatch.setattr(ui, "confirm_without_rollback", lambda detail: False)
    fake_rb = rollback.RollbackResult(True, "system_restore", "throttled")
    monkeypatch.setattr(rollback, "create_rollback_point", lambda spec, tool_input: fake_rb)

    result, is_action = safety.dispatch("approval_tool", {})

    assert calls == []
    assert result == {
        "declined": True,
        "message": "User declined to proceed without a rollback point (throttled).",
    }
    assert is_action is True


def test_approval_tier_rollback_fails_user_proceeds_anyway_func_called(monkeypatch):
    calls = []
    _register_approval_tool(calls)

    monkeypatch.setattr(ui, "confirm_action", lambda spec, tool_input: True)
    monkeypatch.setattr(ui, "confirm_without_rollback", lambda detail: True)
    fake_rb = rollback.RollbackResult(True, "system_restore", "throttled")
    monkeypatch.setattr(rollback, "create_rollback_point", lambda spec, tool_input: fake_rb)

    result, is_action = safety.dispatch("approval_tool", {})

    assert calls == ["ran"]
    assert result["ok"] is True
    assert result["rollback"] == {"method": "system_restore", "detail": "throttled"}
    assert is_action is True


# ---------------------------------------------------------------------------
# BLOCKED tier
# ---------------------------------------------------------------------------

def test_blocked_tier_refused_unconditionally():
    safety.register_blocked(name="blocked_tool", description="never", input_schema=EMPTY_SCHEMA)

    result, is_action = safety.dispatch("blocked_tool", {})

    assert result["error"] is True
    assert "BLOCKED" in result["message"]
    assert is_action is False


def test_blocked_tool_has_no_func_registered():
    safety.register_blocked(name="blocked_tool", description="never", input_schema=EMPTY_SCHEMA)
    assert safety.REGISTRY["blocked_tool"].func is None


def test_register_blocked_never_accepts_a_callable():
    # register_blocked's signature structurally has no `func` parameter at
    # all — there is no way to attach an implementation to a BLOCKED tool.
    with pytest.raises(TypeError):
        safety.register_blocked(
            name="blocked_tool", description="d", input_schema=EMPTY_SCHEMA,
            func=lambda: {"ok": True},
        )


# ---------------------------------------------------------------------------
# Unknown tool name
# ---------------------------------------------------------------------------

def test_unknown_tool_name_refused_cleanly():
    result, is_action = safety.dispatch("does_not_exist", {})

    assert result == {"error": True, "message": "Unknown tool 'does_not_exist'."}
    assert is_action is False


# ---------------------------------------------------------------------------
# Unrecognized tier on an already-registered spec — the Opus-review regression
# ---------------------------------------------------------------------------

def test_unrecognized_tier_on_registered_spec_is_refused_not_executed():
    """The specific bug the Opus review pass found and fixed: dispatch() used
    to fall through to the AUTO branch for any tier that was not exactly
    BLOCKED or APPROVAL, because the AUTO case was the function's default
    exit rather than an explicit membership check.

    register_tool() itself validates the tier at registration time (a bad
    value raises ValueError before this spec could ever land in the
    registry), so to exercise dispatch()'s own defense we bypass that
    validation and insert a malformed ToolSpec directly — simulating a
    corrupted/malformed registry entry reaching dispatch() at call time.
    """
    calls = []

    def rogue_func():
        calls.append("ran")
        return {"ok": True}

    spec = ToolSpec(
        name="rogue_tool",
        description="d",
        input_schema=EMPTY_SCHEMA,
        tier="SOME_UNRECOGNIZED_TIER",  # deliberately not Tier.AUTO/APPROVAL/BLOCKED
        func=rogue_func,
        is_action=True,
    )
    safety.REGISTRY["rogue_tool"] = spec

    result, is_action = safety.dispatch("rogue_tool", {})

    assert calls == [], (
        "dispatch() executed a tool with an unrecognized tier — this is exactly "
        "the fallthrough-to-AUTO regression the Opus review pass fixed."
    )
    assert result["error"] is True
    assert "unrecognized safety tier" in result["message"]
    assert is_action is False


# ---------------------------------------------------------------------------
# register_tool(tier=Tier.BLOCKED, func=...) must raise at registration time
# ---------------------------------------------------------------------------

def test_register_tool_with_blocked_tier_raises_at_registration():
    with pytest.raises(ValueError, match="cannot be registered as BLOCKED"):
        @safety.register_tool(
            name="bad_blocked", description="d", input_schema=EMPTY_SCHEMA, tier=Tier.BLOCKED,
        )
        def bad_blocked():
            return {"ok": True}

    assert "bad_blocked" not in safety.REGISTRY


def test_register_tool_with_blocked_string_tier_also_raises_at_registration():
    # Tier is a str Enum, so a bare string is accepted where it names a real
    # tier — "BLOCKED" must be caught by the BLOCKED-specific guard exactly
    # like Tier.BLOCKED is.
    with pytest.raises(ValueError, match="cannot be registered as BLOCKED"):
        @safety.register_tool(
            name="bad_blocked2", description="d", input_schema=EMPTY_SCHEMA, tier="BLOCKED",
        )
        def bad_blocked2():
            return {"ok": True}


def test_register_tool_with_unknown_tier_string_raises_at_registration():
    with pytest.raises(ValueError, match="unknown safety tier"):
        @safety.register_tool(
            name="bad_tier", description="d", input_schema=EMPTY_SCHEMA, tier="NOT_A_REAL_TIER",
        )
        def bad_tier():
            return {"ok": True}


# ---------------------------------------------------------------------------
# Duplicate tool name registration
# ---------------------------------------------------------------------------

def test_duplicate_name_register_tool_raises_value_error():
    @safety.register_tool(name="dup", description="d1", input_schema=EMPTY_SCHEMA, tier=Tier.AUTO)
    def dup1():
        return {"ok": True}

    with pytest.raises(ValueError, match="Duplicate tool name registered"):
        @safety.register_tool(name="dup", description="d2", input_schema=EMPTY_SCHEMA, tier=Tier.AUTO)
        def dup2():
            return {"ok": True}


def test_duplicate_name_register_blocked_raises_value_error():
    safety.register_blocked(name="dupb", description="d1", input_schema=EMPTY_SCHEMA)

    with pytest.raises(ValueError, match="Duplicate tool name registered"):
        safety.register_blocked(name="dupb", description="d2", input_schema=EMPTY_SCHEMA)


def test_duplicate_name_across_register_tool_and_register_blocked_raises():
    safety.register_blocked(name="shared_name", description="d1", input_schema=EMPTY_SCHEMA)

    with pytest.raises(ValueError, match="Duplicate tool name registered"):
        @safety.register_tool(name="shared_name", description="d2", input_schema=EMPTY_SCHEMA, tier=Tier.AUTO)
        def shared_name_impl():
            return {"ok": True}


# ---------------------------------------------------------------------------
# Malformed arguments refused before func / confirm_action / rollback
# ---------------------------------------------------------------------------

def test_malformed_arguments_refused_before_func_and_confirmation(monkeypatch):
    calls = []

    @safety.register_tool(
        name="strict_tool",
        description="d",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        tier=Tier.APPROVAL,
    )
    def strict_tool(path: str):
        calls.append(path)
        return {"ok": True}

    # confirm_action/rollback would raise if ever reached — proves the
    # argument check happens strictly before the approval machinery.
    monkeypatch.setattr(ui, "confirm_action", _raise)
    monkeypatch.setattr(ui, "confirm_without_rollback", _raise)
    monkeypatch.setattr(rollback, "create_rollback_point", _raise)

    # missing required key
    result, _ = safety.dispatch("strict_tool", {})
    assert result["error"] is True
    assert calls == []

    # extra/unexpected key
    result, _ = safety.dispatch("strict_tool", {"path": "C:\\x", "unexpected": 1})
    assert result["error"] is True
    assert calls == []

    # non-dict input entirely (e.g. agent.py's JSONDecodeError fallback gone wrong)
    result, _ = safety.dispatch("strict_tool", "not-a-dict")  # type: ignore[arg-type]
    assert result["error"] is True
    assert "must be a JSON object" in result["message"]
    assert calls == []


def test_malformed_arguments_refused_for_auto_tool_too(monkeypatch):
    calls = []

    @safety.register_tool(
        name="strict_auto",
        description="d",
        input_schema={
            "type": "object",
            "properties": {"pid": {"type": "integer"}},
            "required": ["pid"],
        },
        tier=Tier.AUTO,
    )
    def strict_auto(pid: int):
        calls.append(pid)
        return {"ok": True}

    result, _ = safety.dispatch("strict_auto", {})
    assert result["error"] is True
    assert calls == []


# ---------------------------------------------------------------------------
# Precheck refusal short-circuits before confirm_action/rollback
# ---------------------------------------------------------------------------

def test_precheck_refusal_short_circuits_before_confirm_and_rollback(monkeypatch):
    calls = []

    def refusing_precheck(tool_input):
        return {"error": True, "message": "refused by precheck"}

    @safety.register_tool(
        name="prechecked_tool",
        description="d",
        input_schema=EMPTY_SCHEMA,
        tier=Tier.APPROVAL,
        precheck=refusing_precheck,
    )
    def prechecked_tool():
        calls.append("ran")
        return {"ok": True}

    monkeypatch.setattr(ui, "confirm_action", _raise)
    monkeypatch.setattr(ui, "confirm_without_rollback", _raise)
    monkeypatch.setattr(rollback, "create_rollback_point", _raise)

    result, is_action = safety.dispatch("prechecked_tool", {})

    assert result == {"error": True, "message": "refused by precheck"}
    assert calls == []
    assert is_action is False  # dispatch() returns spec.is_action here; default is False


def test_precheck_passthrough_none_allows_call_to_proceed(monkeypatch):
    calls = []

    def passing_precheck(tool_input):
        return None

    @safety.register_tool(
        name="prechecked_auto",
        description="d",
        input_schema=EMPTY_SCHEMA,
        tier=Tier.AUTO,
        precheck=passing_precheck,
    )
    def prechecked_auto():
        calls.append("ran")
        return {"ok": True}

    result, _ = safety.dispatch("prechecked_auto", {})
    assert calls == ["ran"]
    assert result == {"ok": True}


def test_precheck_exception_is_caught_and_refuses(monkeypatch):
    calls = []

    def blowing_up_precheck(tool_input):
        raise RuntimeError("precheck exploded")

    @safety.register_tool(
        name="exploding_precheck_tool",
        description="d",
        input_schema=EMPTY_SCHEMA,
        tier=Tier.AUTO,
        precheck=blowing_up_precheck,
    )
    def exploding_precheck_tool():
        calls.append("ran")
        return {"ok": True}

    result, _ = safety.dispatch("exploding_precheck_tool", {})
    assert calls == []
    assert result["error"] is True
    assert "safety pre-check" in result["message"]


# ---------------------------------------------------------------------------
# A raising tool func is caught by dispatch(), not propagated
# ---------------------------------------------------------------------------

def test_raising_tool_func_is_caught_and_returns_structured_error():
    @safety.register_tool(
        name="raising_tool", description="d", input_schema=EMPTY_SCHEMA, tier=Tier.AUTO,
    )
    def raising_tool():
        raise RuntimeError("boom")

    result, is_action = safety.dispatch("raising_tool", {})

    assert result["error"] is True
    assert "RuntimeError" in result["message"]
    assert "boom" in result["message"]


def test_raising_approval_tool_func_is_caught_after_approval_and_rollback(monkeypatch):
    @safety.register_tool(
        name="raising_approval_tool", description="d", input_schema=EMPTY_SCHEMA, tier=Tier.APPROVAL,
    )
    def raising_approval_tool():
        raise ValueError("kaboom")

    monkeypatch.setattr(ui, "confirm_action", lambda spec, tool_input: True)
    fake_rb = rollback.RollbackResult(False, "system_restore", "Restore point created.")
    monkeypatch.setattr(rollback, "create_rollback_point", lambda spec, tool_input: fake_rb)

    result, is_action = safety.dispatch("raising_approval_tool", {})

    assert result["error"] is True
    assert "ValueError" in result["message"]
    assert "kaboom" in result["message"]
    # even a caught-exception result still gets the rollback info attached
    assert result["rollback"] == {"method": "system_restore", "detail": "Restore point created."}
