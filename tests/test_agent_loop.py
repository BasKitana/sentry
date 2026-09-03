"""Tests for agent.run()'s manual DeepSeek tool-calling loop.

The fake client below mimics the shape of the real openai client's
response objects (choices[0].message, choice.finish_reason,
message.tool_calls, tool_call.id/.function.name/.function.arguments) —
nothing from the real `openai` package is imported or used. safety.dispatch
is monkeypatched in every test, so no tool implementation (and therefore no
real service restart, registry write, or process kill) ever actually runs.
"""
import json

import config
import safety
import agent

# Populate safety.REGISTRY as an import side effect (same fixed order
# main.py uses), so agent.build_tools() and the REGISTRY.get(name) lookups
# in agent.run() see the real ToolSpec entries (tier / is_action) for tools
# like "kill_process", "flush_dns", and "get_cpu_usage".
import diagnostics  # noqa: F401
import actions  # noqa: F401
import blocked  # noqa: F401


# ---------------------------------------------------------------------------
# Fake OpenAI-shaped client
# ---------------------------------------------------------------------------

class FakeFunction:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments  # JSON string, exactly like the real API


class FakeToolCall:
    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.function = FakeFunction(name, arguments)


class FakeMessage:
    def __init__(self, content=None, tool_calls=None, role="assistant"):
        self.content = content
        self.tool_calls = tool_calls
        self.role = role

    def model_dump(self, exclude_none=True):
        d = {"role": self.role}
        if not exclude_none or self.content is not None:
            d["content"] = self.content
        if self.tool_calls:
            d["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in self.tool_calls
            ]
        elif not exclude_none:
            d["tool_calls"] = None
        return d


class FakeChoice:
    def __init__(self, message, finish_reason):
        self.message = message
        self.finish_reason = finish_reason


class FakeResponse:
    def __init__(self, message, finish_reason):
        self.choices = [FakeChoice(message, finish_reason)]


class FakeCompletions:
    """`handler(call_index, **kwargs) -> FakeResponse` drives every call.
    Every call's kwargs (model, messages, tools, tool_choice, max_tokens)
    are recorded in `.calls` for later assertion."""

    def __init__(self, handler):
        self._handler = handler
        self.calls = []

    def create(self, **kwargs):
        idx = len(self.calls)
        self.calls.append(kwargs)
        return self._handler(idx, **kwargs)


class FakeChat:
    def __init__(self, completions):
        self.completions = completions


class FakeClient:
    def __init__(self, handler):
        self.chat = FakeChat(FakeCompletions(handler))


# ---------------------------------------------------------------------------
# 1. Off-topic prompt: immediate finish_reason="stop", dispatch never called
# ---------------------------------------------------------------------------

def test_off_topic_prompt_returns_text_on_first_call_without_dispatch(monkeypatch):
    def _no_dispatch(name, tool_input):
        raise AssertionError("safety.dispatch should never be called when the model just answers")
    monkeypatch.setattr(safety, "dispatch", _no_dispatch)

    def handler(idx, **kwargs):
        assert idx == 0
        return FakeResponse(FakeMessage(content="I can only help with this PC's health, not that."), "stop")

    client = FakeClient(handler)
    result = agent.run(client, "What's the capital of France?", model="fake-model")

    assert result == "I can only help with this PC's health, not that."
    assert len(client.chat.completions.calls) == 1
    assert client.chat.completions.calls[0]["tool_choice"] == "auto"


# ---------------------------------------------------------------------------
# 2. tool_choice flips to "none" on the request AFTER an action resolves
# ---------------------------------------------------------------------------

def test_tool_choice_becomes_none_on_request_after_action_resolves(monkeypatch):
    dispatch_calls = []

    def fake_dispatch(name, tool_input):
        dispatch_calls.append((name, tool_input))
        return {"flushed": True, "message": "DNS resolver cache flushed."}, True

    monkeypatch.setattr(safety, "dispatch", fake_dispatch)

    def handler(idx, **kwargs):
        if idx == 0:
            assert kwargs["tool_choice"] == "auto"
            tc = FakeToolCall("call_1", "flush_dns", "{}")
            return FakeResponse(FakeMessage(tool_calls=[tc]), "tool_calls")
        if idx == 1:
            return FakeResponse(FakeMessage(content="Flushed the DNS cache; try the site again."), "stop")
        raise AssertionError(f"unexpected extra call at index {idx}")

    client = FakeClient(handler)
    result = agent.run(client, "DNS seems broken", model="fake-model")

    assert result == "Flushed the DNS cache; try the site again."
    assert dispatch_calls == [("flush_dns", {})]
    assert len(client.chat.completions.calls) == 2
    # The load-bearing assertion: the request that FOLLOWS the resolved
    # action must pass tool_choice="none", not "auto".
    assert client.chat.completions.calls[1]["tool_choice"] == "none"


# ---------------------------------------------------------------------------
# 3. Malformed tool_call arguments -> empty dict, not a crash
# ---------------------------------------------------------------------------

def test_malformed_tool_call_arguments_become_empty_dict(monkeypatch):
    captured = []

    def fake_dispatch(name, tool_input):
        captured.append((name, tool_input))
        return {"percent": 12.0, "core_count_logical": 8}, False

    monkeypatch.setattr(safety, "dispatch", fake_dispatch)

    def handler(idx, **kwargs):
        if idx == 0:
            tc = FakeToolCall("call_1", "get_cpu_usage", "{not valid json at all")
            return FakeResponse(FakeMessage(tool_calls=[tc]), "tool_calls")
        return FakeResponse(FakeMessage(content="CPU usage looks normal."), "stop")

    client = FakeClient(handler)
    result = agent.run(client, "Is my CPU pegged?", model="fake-model")

    assert result == "CPU usage looks normal."
    assert captured == [("get_cpu_usage", {})]


# ---------------------------------------------------------------------------
# 4. MAX_ITERATIONS exhausted -> step-limit fallback, not a hang/crash
# ---------------------------------------------------------------------------

def test_max_iterations_exhausted_returns_step_limit_message(monkeypatch):
    monkeypatch.setattr(safety, "dispatch", lambda name, tool_input: ({"percent": 5}, False))

    def handler(idx, **kwargs):
        # Always proposes another tool call, never finishes -> the loop's
        # own iteration bound must be what stops it, not the model.
        tc = FakeToolCall(f"call_{idx}", "get_cpu_usage", "{}")
        return FakeResponse(FakeMessage(tool_calls=[tc]), "tool_calls")

    client = FakeClient(handler)
    result = agent.run(client, "it keeps happening", model="fake-model")

    assert result == "Reached the step limit without a final answer — try rephrasing the problem."
    assert len(client.chat.completions.calls) == config.MAX_ITERATIONS


# ---------------------------------------------------------------------------
# 5. Parallel tool calls in one message: only the first is_action call
#    reaches safety.dispatch; later ones in the same message are refused
#    locally by agent.run() itself.
# ---------------------------------------------------------------------------

def test_parallel_tool_calls_only_first_action_reaches_dispatch(monkeypatch):
    dispatch_calls = []

    def fake_dispatch(name, tool_input):
        dispatch_calls.append(name)
        return {"ok": True, "tool": name}, True

    monkeypatch.setattr(safety, "dispatch", fake_dispatch)
    # ui.narrate is only called for the call that actually reaches
    # dispatch(); leave it real (it just prints) rather than mocking it,
    # to keep this test focused on the dispatch-call-count assertion.

    def handler(idx, **kwargs):
        if idx == 0:
            tc1 = FakeToolCall("call_1", "kill_process", json.dumps({"pid": 111}))
            tc2 = FakeToolCall("call_2", "flush_dns", "{}")
            return FakeResponse(FakeMessage(tool_calls=[tc1, tc2]), "tool_calls")
        return FakeResponse(FakeMessage(content="Handled the frozen app and the DNS issue."), "stop")

    client = FakeClient(handler)
    result = agent.run(client, "an app is frozen and DNS is broken", model="fake-model")

    assert result == "Handled the frozen app and the DNS issue."
    # Exactly one is_action tool call reached dispatch, despite two being
    # proposed in the same message.
    assert dispatch_calls == ["kill_process"]

    # The second tool result (sent back on the following request) must be
    # the local "already resolved" refusal, not a real dispatch() result.
    second_call_messages = client.chat.completions.calls[1]["messages"]
    tool_messages = {m["tool_call_id"]: m for m in second_call_messages if m.get("role") == "tool"}

    first_result = json.loads(tool_messages["call_1"]["content"])
    assert first_result == {"ok": True, "tool": "kill_process"}

    refusal = json.loads(tool_messages["call_2"]["content"])
    assert refusal["error"] is True
    assert "already" in refusal["message"].lower()


# ---------------------------------------------------------------------------
# 6. Empty final response with no prior tool calls -> bare placeholder,
#    no nudge attempted (nothing was gathered to summarize or retry over).
# ---------------------------------------------------------------------------

def test_empty_response_with_no_prior_tool_calls_returns_placeholder_no_nudge():
    def handler(idx, **kwargs):
        assert idx == 0, "should not retry when nothing was ever gathered"
        return FakeResponse(FakeMessage(content=None), "stop")

    client = FakeClient(handler)
    result = agent.run(client, "hello", model="fake-model")

    assert result == "(no response text)"
    assert len(client.chat.completions.calls) == 1


# ---------------------------------------------------------------------------
# 7. Empty final response AFTER real tool calls -> one nudge retry; if the
#    retry produces real content, that's what's returned.
# ---------------------------------------------------------------------------

def test_empty_response_after_tool_calls_is_nudged_and_recovers(monkeypatch):
    monkeypatch.setattr(safety, "dispatch", lambda name, tool_input: ({"percent": 20.0}, False))

    def handler(idx, **kwargs):
        if idx == 0:
            tc = FakeToolCall("call_1", "get_cpu_usage", "{}")
            return FakeResponse(FakeMessage(tool_calls=[tc]), "tool_calls")
        if idx == 1:
            # Model stalls: finish_reason isn't tool_calls, but content is empty.
            return FakeResponse(FakeMessage(content=None), "stop")
        if idx == 2:
            # The nudge message must be the one that provoked this retry.
            assert kwargs["messages"][-1]["content"].startswith("You investigated")
            return FakeResponse(FakeMessage(content="CPU is at 20%, nothing to fix."), "stop")
        raise AssertionError(f"unexpected extra call at index {idx}")

    client = FakeClient(handler)
    result = agent.run(client, "check everything", model="fake-model")

    assert result == "CPU is at 20%, nothing to fix."
    assert len(client.chat.completions.calls) == 3


# ---------------------------------------------------------------------------
# 8. Empty final response persists even after the nudge -> a synthesized
#    summary built from the real tool results, never the bare placeholder,
#    since real work was done and shouldn't be thrown away silently.
# ---------------------------------------------------------------------------

def test_empty_response_persists_after_nudge_falls_back_to_tool_summary(monkeypatch):
    monkeypatch.setattr(safety, "dispatch", lambda name, tool_input: ({"percent": 42.0}, False))

    def handler(idx, **kwargs):
        if idx == 0:
            tc = FakeToolCall("call_1", "get_cpu_usage", "{}")
            return FakeResponse(FakeMessage(tool_calls=[tc]), "tool_calls")
        # Both the original response and the post-nudge response are empty —
        # only one nudge is ever attempted.
        return FakeResponse(FakeMessage(content=None), "stop")

    client = FakeClient(handler)
    result = agent.run(client, "check everything", model="fake-model")

    assert result != "(no response text)"
    assert "get cpu usage" in result
    assert '"percent": 42.0' in result
    # Exactly one nudge: call 0 (tool call) + call 1 (empty, triggers nudge)
    # + call 2 (still empty, gives up) = 3 calls, not more.
    assert len(client.chat.completions.calls) == 3


# ---------------------------------------------------------------------------
# 9. history=None (every test above): a fresh, memory-free history every
#    call, matching the pre-memory behavior exactly.
# ---------------------------------------------------------------------------

def test_no_history_passed_starts_fresh_each_call():
    def handler(idx, **kwargs):
        assert idx == 0
        # Exactly system + this call's user message — no memory of anything
        # that isn't this call, matching every pre-existing test's assumption.
        assert len(kwargs["messages"]) == 2
        assert kwargs["messages"][0] == {"role": "system", "content": agent.SYSTEM_PROMPT}
        assert kwargs["messages"][1] == {"role": "user", "content": "first question"}
        return FakeResponse(FakeMessage(content="answer one"), "stop")

    client = FakeClient(handler)
    agent.run(client, "first question", model="fake-model")

    # A second, independent call with no history: still starts fresh, no
    # trace of the first call's question.
    def handler2(idx, **kwargs):
        assert len(kwargs["messages"]) == 2
        assert kwargs["messages"][1] == {"role": "user", "content": "second question"}
        return FakeResponse(FakeMessage(content="answer two"), "stop")

    client2 = FakeClient(handler2)
    agent.run(client2, "second question", model="fake-model")


# ---------------------------------------------------------------------------
# 10. history=<same list across calls>: real short-term memory — a later
#     call's request actually includes the earlier turn's content, and the
#     final answer references it as if it remembered.
# ---------------------------------------------------------------------------

def test_shared_history_across_two_calls_carries_memory(monkeypatch):
    monkeypatch.setattr(safety, "dispatch",
                         lambda name, tool_input: ({"name": "Docker Desktop", "enabled": True}, False))

    def handler(idx, **kwargs):
        if idx == 0:
            tc = FakeToolCall("call_1", "list_startup_items", "{}")
            return FakeResponse(FakeMessage(tool_calls=[tc]), "tool_calls")
        return FakeResponse(FakeMessage(content="Docker Desktop is a startup item using RAM."), "stop")

    client = FakeClient(handler)
    history = agent.new_history()
    first = agent.run(client, "what's using my RAM", model="fake-model", history=history)
    assert first == "Docker Desktop is a startup item using RAM."

    # Second call, same history object: the follow-up's request must include
    # everything from the first call (system + user + assistant tool_calls +
    # tool result + first answer) plus the new question — that's the actual
    # mechanism of memory, not just a claim.
    def handler2(idx, **kwargs):
        msgs = kwargs["messages"]
        assert msgs[0] == {"role": "system", "content": agent.SYSTEM_PROMPT}
        assert msgs[1] == {"role": "user", "content": "what's using my RAM"}
        assert any(m.get("role") == "tool" and "Docker Desktop" in m["content"] for m in msgs)
        assert {"role": "assistant", "content": "Docker Desktop is a startup item using RAM."} in msgs
        assert msgs[-1] == {"role": "user", "content": "what would disabling it do"}
        return FakeResponse(FakeMessage(content="It just won't launch at sign-in; you can still open it anytime."), "stop")

    client2 = FakeClient(handler2)
    second = agent.run(client2, "what would disabling it do", model="fake-model", history=history)
    assert second == "It just won't launch at sign-in; you can still open it anytime."

    # And the shared history object itself grew across both calls — the
    # exact mutation-in-place mechanism main.py relies on.
    assert len(history) > 4
