"""Your Own AI I.T. — agent loop: the manual DeepSeek tool-calling loop.

Zero OS-touching code lives here. The model only ever sees JSON tool
schemas (built from safety.REGISTRY) and JSON tool results (from
safety.dispatch). All actual system access happens in diagnostics.py /
actions.py / blocked.py behind the safety gate in safety.py.
"""
import json

import config
import safety
import ui

SYSTEM_PROMPT = """You are Your Own AI I.T., a Windows system-health assistant running on the \
user's own PC. You have NO shell, filesystem, or OS access except through the tools provided \
— every tool call is intercepted and safety-checked by the application before anything runs; \
you cannot bypass this by asking differently.

Tools are tiered: AUTO tools run immediately. APPROVAL tools require the user's explicit \
yes/no and get a rollback point created first. BLOCKED tools are refused unconditionally — \
if one is refused, do not argue or suggest workarounds; explain the refusal and, if possible, \
suggest a safer manual alternative.

Workflow: (1) call read-only diagnostic tools to investigate before proposing anything. \
Call only the diagnostics relevant to the reported problem — do not run a full system sweep \
for a narrow issue; each extra call costs the user real money and time. \
(2) Propose and call EXACTLY ONE action tool that best addresses the root cause. \
(3) Once you have that tool's result (or a refusal/decline), report plainly to the user what \
you found, what happened, and what to check next. Never claim an action succeeded unless the \
tool result says so.

You are software only — you can inspect and fix software/OS-level issues (processes, startup \
items, temp files, services, settings) but you have no way to act on hardware (a failing \
drive, bad RAM, thermal throttling, a dying fan or battery). If diagnostics point toward a \
likely hardware cause, say so plainly and recommend the user get it physically checked — do \
not suggest a software action as if it might fix a hardware problem, and never imply you \
performed a hardware fix.

Always finish with a real answer for the user, even when nothing needs fixing — after you've \
investigated, you must produce a final text summary. Never end a turn with tool calls and no \
following explanation.

Output style: keep it short. For a full health check (the startup scan, or when explicitly \
asked to check everything), present findings as a compact table — metric, reading, one-word \
status — and nothing else; do not also restate each row as prose afterward. For any other \
question, skip the table and answer in a few plain sentences. In both cases: if something \
genuinely needs attention, state it plainly and either propose your one fix or say what to \
check next. If nothing needs fixing, say that in one short sentence and stop there — do not \
list voluntary/optional cleanups, do not pad with reassurance, do not suggest a low-value \
action just to have something to offer. You may have earlier turns in this conversation — use \
that context (e.g. "it" can refer to something you already found or mentioned) instead of \
asking the user to repeat themselves."""


def build_tools() -> list[dict]:
    return [{
        "type": "function",
        "function": {"name": s.name, "description": s.description, "parameters": s.input_schema},
    } for s in safety.REGISTRY.values()]


def new_history() -> list[dict]:
    """A fresh conversation history, seeded with the system prompt. Pass the
    same list back into run() across multiple calls to keep short-term
    memory within one session (main.py does this for follow-up questions) —
    without it, every call starts from zero and "it"/"that" in a follow-up
    has nothing to resolve against."""
    return [{"role": "system", "content": SYSTEM_PROMPT}]


def _fallback_summary(tool_call_log: list[tuple[str, dict]]) -> str:
    """Build a plain-text summary directly from what was actually gathered,
    for the worst case where the model never produced final text at all
    (even after the one-shot nudge in run()). A session that did real work
    should never hand the user a bare "no response" — this is Python
    formatting the tool's own structured results, not the model talking."""
    if not tool_call_log:
        return "(no response text)"
    lines = ["I gathered the following before losing the connection to a final answer:"]
    for name, result in tool_call_log:
        label = name.replace("_", " ")
        lines.append(f"- {label}: {json.dumps(result, default=str)}")
    lines.append("\nNo AI-written analysis was produced for this data — try asking again.")
    return "\n".join(lines)


def run(client, user_problem: str, model: str = config.DEFAULT_MODEL,
        history: list[dict] | None = None) -> str:
    """Run one turn. `history` is mutated in place (a new user message is
    appended, then every assistant/tool message the loop produces) so the
    caller's own reference keeps growing — pass the same list back in on the
    next call for short-term memory across a session. Leave it None for a
    one-shot, memory-free call (each existing caller that doesn't pass it
    keeps working exactly as before)."""
    tools = build_tools()
    messages = new_history() if history is None else history
    messages.append({"role": "user", "content": user_problem})
    action_resolved = False
    any_tool_called = False
    nudged = False
    tool_call_log: list[tuple[str, dict]] = []

    for _ in range(config.MAX_ITERATIONS):
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tools,
            tool_choice="none" if action_resolved else "auto",
            max_tokens=config.MAX_TOKENS,
        )
        choice = response.choices[0]
        msg = choice.message
        messages.append(msg.model_dump(exclude_none=True))

        if choice.finish_reason != "tool_calls" or not msg.tool_calls:
            if msg.content:
                return msg.content
            # Empty final text after real tool calls were already made: observed live
            # against the real DeepSeek API (not yet root-caused — finish_reason and
            # raw content logged below so the next occurrence carries evidence, not just
            # a repro description). Rather than silently giving up on a session that did
            # real work, nudge once for the summary it should have already given.
            ui.narrate_debug(
                f"empty final response (finish_reason={choice.finish_reason!r}, "
                f"content={msg.content!r}, tool calls so far: {any_tool_called})"
            )
            if any_tool_called and not nudged:
                nudged = True
                messages.append({
                    "role": "user",
                    "content": "You investigated but gave no final answer. Summarize what "
                               "you found now, in plain text, and either propose one fix or "
                               "say plainly that nothing needs fixing.",
                })
                continue
            return _fallback_summary(tool_call_log)

        any_tool_called = True
        for tool_call in msg.tool_calls:
            name = tool_call.function.name
            try:
                tool_input = json.loads(tool_call.function.arguments or "{}")
            except json.JSONDecodeError:
                tool_input = {}
            # `tool_choice="none"` stops the model proposing another action on
            # a LATER turn, but it cannot stop it emitting several tool calls
            # in a SINGLE message (parallel tool calling), which would run
            # every one of them — including AUTO actions, which carry no
            # confirmation prompt. Enforce the "exactly one action" rule here
            # too, so the invariant holds within a turn as well as across
            # turns. BLOCKED tools still go to dispatch() so the model gets
            # the real refusal reason rather than this message.
            spec = safety.REGISTRY.get(name)
            if (action_resolved and spec is not None and spec.is_action
                    and spec.tier != safety.Tier.BLOCKED):
                result = {
                    "error": True,
                    "message": f"Refused: an action has already been taken for this problem, so "
                               f"'{name}' was not run. Only one action tool may run per problem — "
                               f"report the result you already have instead.",
                }
            else:
                ui.narrate(name, tool_input)
                result, resolved = safety.dispatch(name, tool_input)
                action_resolved = action_resolved or resolved
                tool_call_log.append((name, result))
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(result, default=str),
            })

    return "Reached the step limit without a final answer — try rephrasing the problem."
