"""Your Own AI IT — tool registry and safety-tier enforcement (the gate).

This is the one module every tool call from the model must pass through.
The model never gets raw shell/OS access; it can only name a registered
tool and supply arguments, and this file decides — based on the tool's
declared Tier, never on the model's own judgment — whether that call runs
immediately, requires human approval (with a rollback point created
first), or is refused outright with no implementation to fall back on.

diagnostics.py, actions.py, and blocked.py populate REGISTRY as an import
side effect; main.py must `import diagnostics, actions, blocked  # noqa: F401`
before building the tool list so every tool is registered.
"""

import inspect
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional


class Tier(str, Enum):
    AUTO = "AUTO"
    APPROVAL = "APPROVAL"
    BLOCKED = "BLOCKED"


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict
    tier: Tier
    func: Optional[Callable]     # None for BLOCKED — no implementation exists, period
    is_action: bool              # drives the "exactly one action" cutoff
    restore_point_type: int = 12 # WMI RestorePointType; 12 = MODIFY_SETTINGS
    # Optional target validation that runs BEFORE the approval prompt and
    # before any rollback point is created. Takes the tool_input dict and
    # returns a refusal result dict, or None to allow the call to proceed.
    # This is what lets a doomed call (a critical PID, a protected path, an
    # unimplemented stub) be refused without spending the user's attention on
    # a pointless confirmation or spending their one-per-24h restore point.
    # Tools keep their own internal checks too — this is an extra early gate,
    # not a replacement for defense in depth.
    precheck: Optional[Callable] = None


REGISTRY: dict[str, ToolSpec] = {}


def register_tool(name, description, input_schema, tier, is_action=False, restore_point_type=12,
                  precheck=None):
    # Coerce/validate the tier at registration time. dispatch() refuses any
    # tier it does not recognize, but catching a bad tier here — at import,
    # loudly — is better than discovering it as a refused tool call at
    # runtime. A bare string like "AUTO" is accepted (Tier is a str Enum);
    # anything that is not a real tier is a hard error.
    try:
        tier = Tier(tier)
    except ValueError:
        raise ValueError(
            f"Tool '{name}' declares an unknown safety tier {tier!r}. "
            f"Must be one of: {', '.join(t.value for t in Tier)}."
        ) from None

    # BLOCKED means "no implementation exists, period" — that guarantee is
    # structural (see blocked.py), so it must not be reachable through the
    # decorator that attaches a callable. Use register_blocked() instead.
    if tier == Tier.BLOCKED:
        raise ValueError(
            f"Tool '{name}' cannot be registered as BLOCKED with an implementation. "
            f"BLOCKED tools must be declared via register_blocked(), which never "
            f"accepts a callable."
        )

    def decorator(func):
        if name in REGISTRY:
            raise ValueError(f"Duplicate tool name registered: {name}")
        REGISTRY[name] = ToolSpec(name, description, input_schema, tier, func, is_action,
                                  restore_point_type, precheck)
        return func
    return decorator


def register_blocked(name, description, input_schema):
    if name in REGISTRY:
        raise ValueError(f"Duplicate tool name registered: {name}")
    REGISTRY[name] = ToolSpec(name, description, input_schema, Tier.BLOCKED, None, True)


def _argument_error(spec: ToolSpec, tool_input: dict) -> Optional[dict]:
    """Check the model's arguments against the tool's real signature BEFORE
    anything happens.

    Two reasons this must run early rather than being left to the TypeError
    that spec.func(**tool_input) would raise anyway:

    1. Unhandled: that TypeError escapes dispatch() and kills the whole
       session with a traceback. The model produces these routinely — a
       hallucinated extra argument, a missing required one, or agent.py's
       own `except json.JSONDecodeError: tool_input = {}` fallback, which
       hands every tool an empty dict.
    2. Out of order: for an APPROVAL tool the failure would land *after*
       the user was prompted to approve the call and after a System Restore
       point was created for it — burning the once-per-24h restore point on
       a call that was never going to run.
    """
    if not isinstance(tool_input, dict):
        return {"error": True, "message": f"Arguments for '{spec.name}' must be a JSON object."}
    try:
        inspect.signature(spec.func).bind(**tool_input)
    except TypeError as e:
        return {
            "error": True,
            "message": f"Invalid arguments for '{spec.name}': {e}. Nothing was run. "
                       f"Check the tool's schema and call it again with the correct arguments.",
        }
    return None


def _invoke(spec: ToolSpec, tool_input: dict) -> dict:
    """Run a tool implementation, converting any unhandled exception into a
    structured result. A tool that raises must not take the session down with
    it: the model gets told the call failed and can report that honestly."""
    try:
        result = spec.func(**tool_input)
    except Exception as e:  # noqa: BLE001 - a raising tool must not kill the session
        return {"error": True, "message": f"'{spec.name}' failed: {type(e).__name__}: {e}"}
    if not isinstance(result, dict):
        return {"error": True, "message": f"'{spec.name}' returned a non-dict result: {result!r}"}
    return result


def dispatch(name: str, tool_input: dict) -> tuple[dict, bool]:
    spec = REGISTRY.get(name)
    if spec is None:
        return {"error": True, "message": f"Unknown tool '{name}'."}, False

    if spec.tier == Tier.BLOCKED:
        return {"error": True, "message": f"BLOCKED: {spec.description} This cannot be done, "
                                           f"now or with any future override."}, False

    # Fail closed on anything unexpected, BEFORE any branch that can execute.
    # A BLOCKED-tier spec is the only one allowed to have no implementation;
    # a missing func anywhere else means the registry is malformed, and
    # calling None would only produce a confusing TypeError.
    if spec.func is None:
        return {"error": True, "message": f"Refused: '{name}' has no implementation."}, False

    # An unrecognized tier must never reach an execute branch. This used to be
    # a fallthrough: the AUTO path was the function's default exit, so any
    # spec whose tier was not exactly BLOCKED or APPROVAL ran immediately with
    # no confirmation. Tiers are now matched explicitly and anything else is
    # refused.
    if spec.tier not in (Tier.AUTO, Tier.APPROVAL):
        return {"error": True, "message": f"Refused: '{name}' has an unrecognized safety tier "
                                          f"({spec.tier!r}); refusing rather than guessing."}, False

    arg_error = _argument_error(spec, tool_input)
    if arg_error is not None:
        return arg_error, False

    # Target validation, before the user is asked anything and before any
    # rollback point is created. Without this, a call that was always going to
    # be refused (a critical PID, a protected path, an unimplemented stub)
    # still prompted the user and still created a System Restore point —
    # and Windows only allows about one of those per 24h, so a refused call
    # could leave the next genuine action with no safety net.
    if spec.precheck is not None:
        try:
            refusal = spec.precheck(tool_input)
        except Exception as e:  # noqa: BLE001 - a failing check must refuse, not crash
            refusal = {"error": True, "message": f"Refused: safety pre-check for '{name}' failed "
                                                 f"({type(e).__name__}: {e})."}
        if refusal is not None:
            return refusal, spec.is_action

    if spec.tier == Tier.APPROVAL:
        # Local imports: avoids a circular import at module load time (ui.py's
        # confirm_action()/confirm_without_rollback() take a ToolSpec, and
        # rollback.py's create_rollback_point() takes one too — neither needs
        # to import safety at module scope).
        #
        # This does NOT avoid loading pywin32 on non-APPROVAL paths, despite
        # what an earlier version of this comment claimed: actions.py imports
        # rollback at module scope (for BACKUP_ROOT) and diagnostics.py
        # imports win32com.client directly, so both are already loaded by the
        # time any dispatch happens. The deferral here is purely about the
        # import cycle.
        import rollback
        import ui

        if not ui.confirm_action(spec, tool_input):
            return {"declined": True, "message": "User declined. No changes made."}, True
        rb = rollback.create_rollback_point(spec, tool_input)
        if rb.failed and not ui.confirm_without_rollback(rb.detail):
            return {"declined": True, "message": f"User declined to proceed without a rollback point ({rb.detail})."}, True
        result = _invoke(spec, tool_input)
        result["rollback"] = {"method": rb.method, "detail": rb.detail}
        return result, True

    # AUTO — the only remaining tier, reached only after the explicit
    # membership check above.
    return _invoke(spec, tool_input), spec.is_action
