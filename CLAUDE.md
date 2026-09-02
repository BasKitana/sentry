# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

S.E.N.T.R.Y. is a local, single-user Windows CLI tool: the user describes a problem in plain language, a DeepSeek-V4-Flash agent investigates via read-only diagnostics, proposes one fix, and a Python-side safety gate decides whether it runs immediately, needs the user's approval, or is refused outright. The model never gets shell/OS access — only named, schema-defined tool calls that pass through `safety.dispatch()`.

v1 is personal-use only (single Anthropic-style `.env` key, no multi-user/billing layer). A UI and productization are explicitly out of scope for the current codebase.

## Commands

```powershell
# Setup
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt          # unpinned — see "Known state" below
copy .env.example .env                   # then fill in DEEPSEEK_API_KEY

# Run
python main.py

# There is no automated test suite (pytest, etc.) yet. Ad-hoc verification used during
# development and worth reusing when touching this code:
py -m py_compile <file>.py               # syntax check a single file
.venv\Scripts\python -c "import safety, diagnostics, actions, blocked; print(len(safety.REGISTRY))"
                                          # registry sanity check — should print 22, no
                                          # Duplicate tool name registered error
```

## Architecture

**The gate is `safety.py`.** Every tool call from the model — whatever agent.py's loop received from DeepSeek — passes through `safety.dispatch(name, tool_input)`. This is the only code path that ever calls a tool's real `func`. Three tiers, enforced by explicit membership check (not a fallthrough — an unrecognized tier is refused, not treated as AUTO):
- **AUTO** — runs immediately.
- **APPROVAL** — `ui.confirm_action()` first, then `rollback.create_rollback_point()` (System Restore point via WMI, or a file copy for path-based actions) before `func` runs.
- **BLOCKED** — refused unconditionally. `register_blocked()` never accepts a `func` at all, so the guarantee is structural (nothing to call), not just a tier check that could be bypassed.

Tools additionally carry an optional `precheck` (`ToolSpec.precheck`), which runs *before* the approval prompt and *before* a rollback point is created — so a call that was always going to be refused (a critical PID, a protected path, an unimplemented stub) doesn't burn the user's attention or Windows' ~1-per-24h System Restore point on something that was never going to execute. Precheck is defense in depth on top of each tool's own internal validation, not a replacement for it — several tools (`kill_process`, `restart_unresponsive_process`, `move_to_recycle_bin`, `permanently_delete_file`, `set_startup_item_enabled`) validate their specific target internally as well.

**Module boundary**: `agent.py` + `config.py` are the only files that talk to the LLM API — zero OS-touching code. Everything else (`diagnostics.py`, `actions.py`, `blocked.py`, `safety.py`, `rollback.py`, `ui.py`) is the system-control layer; the model only ever sees the JSON tool schemas `agent.build_tools()` derives from `safety.REGISTRY` and the JSON results `dispatch()` returns.

**Registry population is import-order dependent.** `diagnostics.py`, `actions.py`, and `blocked.py` populate `safety.REGISTRY` as a decorator side effect at import time — nothing is registered until they're imported. `main.py` does `import diagnostics, actions, blocked  # noqa: F401` before anything calls `agent.build_tools()`. This fixed order also keeps `REGISTRY` iteration order (and therefore the serialized `tools` array sent to the API) identical byte-for-byte across every process run and every user session — load-bearing for DeepSeek's automatic prefix caching (see below), not just a style choice.

**The agent loop (`agent.py`) is a manual loop, not a library-driven one** — deliberate, because the safety gate for an APPROVAL call is a multi-step sequence (confirm → rollback point → execute → verify) that wants one call site the loop owns directly. DeepSeek speaks the OpenAI Chat Completions wire format (`client.chat.completions.create`, not an Anthropic-style API): `tool_choice` is the string `"auto"`/`"none"`; `tool_call.function.arguments` is a JSON string requiring `json.loads()` (wrapped in `try/except JSONDecodeError` — a malformed-arguments case DeepSeek produces routinely enough that `safety._argument_error()` re-validates against the real function signature anyway); tool results go back as individual `{"role": "tool", ...}` messages. `tool_choice="none"` only stops the model proposing another action on a *later* turn — it can't stop several tool calls in one message (parallel tool calling), so `agent.run()` additionally enforces "exactly one action per problem" itself once `action_resolved` is set.

**Cost design**: the system prompt is a fixed constant and `tools` is built from the deterministic registry order above, so that whole prefix is byte-identical across requests — DeepSeek's context caching (automatic, no code required, ~15x cheaper on a cache hit) applies to it for free, both within a session and across different sessions/users later. `MAX_TOKENS=4096` and no "thinking mode" are deliberate — this is a structured tool-classification task, not long-form generation. The system prompt explicitly tells the model to call only the diagnostics the reported problem needs, not sweep everything.

**Undocumented Windows API notes** (verify against a real machine if touching this code): `set_startup_item_enabled` writes the `StartupApproved\Run`/`StartupApproved\StartupFolder` binary flag directly (Microsoft doesn't document this format) — it preserves the original value's exact byte length, backs it up before writing, and reads back after to confirm. `rollback.create_system_restore_point` calls the WMI `SystemRestore` class's `CreateRestorePoint` directly (what `Checkpoint-Computer` wraps); Windows throttles this to ~1 per 24h by default, and `dispatch()` treats a throttled/failed restore point as an expected outcome requiring extra user confirmation, not a bug.

## Known state (not yet done)

- `requirements.txt` is now pinned to the exact versions verified working (`openai==3.7.0`, `psutil==7.2.2`, `pywin32==312`, `send2trash==2.1.0`, `rich==15.0.0`, `python-dotenv==1.2.3`). `requirements-dev.txt` holds `pytest==9.1.1`, kept separate so end users don't need a test runner.
- Automated test suite exists: `tests/` (85 tests, pytest, fully mocked — no live API calls, no real Windows state touched). Run with `.venv\Scripts\python -m pytest tests\ -v`.
- **Live DeepSeek round-trip — partially verified, one real bug found.** A simple diagnostic request worked end-to-end correctly (investigated, gave a clean final summary, no wasted calls). A broader "make it faster" request made 5 read-only tool calls and then returned an **empty final response** (`finish_reason` not `tool_calls`, `msg.content` falsy) — not yet root-caused. Mitigated, not fixed: `agent.run()` now logs the raw `finish_reason`/content via `ui.narrate_debug()` and nudges the model once with an explicit "summarize now" follow-up message before giving up, rather than silently returning `"(no response text)"`. If this recurs, the debug line printed to the console is the first thing to look at — it wasn't captured the first time this happened, so the root cause is still unconfirmed.
- `restart_unresponsive_process` relaunches via `subprocess.Popen([exe])`, which drops the original command-line arguments/working directory and makes the relaunched app a child of SENTRY (inheriting its privilege level).
- `set_startup_item_enabled` backs up the previous registry value to a `.hex` file that nothing currently reads back automatically — restoring it today is a manual `reg` operation.
- `main.py` now runs an automatic startup health scan (`_STARTUP_SCAN_PROMPT`) before prompting, then loops asking "anything else?" until the user presses Enter with nothing typed. Each `agent.run()` call is still independent — no conversation memory carries between the startup scan and a follow-up question, or between two follow-up questions.
