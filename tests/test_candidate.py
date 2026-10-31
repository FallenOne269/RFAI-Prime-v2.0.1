"""Scripted-backend tests for the v2.0.2 candidate. No model, no key, no network."""
import asyncio
import json
import sys
import types
from pathlib import Path

import pytest


class FakeClient:
    """Replies by role. `script` maps role -> callable(prompt, n) -> text."""
    script = {}

    def __init__(self, api_key=None):
        self.calls = []
        self.messages = self

    def create(self, model, max_tokens, messages):
        prompt = messages[0]["content"]
        role = prompt.split(" in the RFAI-PRIME council")[0].replace("You are the ", "")
        n = sum(1 for r, _ in self.calls if r == role)
        self.calls.append((role, prompt))
        fn = FakeClient.script.get(role) or FakeClient.script.get("critic" if "Critic" in role else role)
        text = fn(prompt, n)
        if isinstance(text, Exception):
            raise text
        return types.SimpleNamespace(content=[types.SimpleNamespace(text=text)])


sys.modules["anthropic"] = types.SimpleNamespace(Anthropic=FakeClient)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src import rfai_prime_runtime as rt  # noqa: E402


def crit(score):
    return lambda p, n: json.dumps({"perspective": "x", "score": score, "feedback": "f", "suggestions": []})


def run(council, task="T"):
    return asyncio.run(council.invoke(task))


def make(**kw):
    return rt.RFAIPrimeCouncil(api_key="k", **kw)


# ---- W1 parsing ---------------------------------------------------------

def test_unreadable_reply_is_none_not_five():
    f = rt.parse_critic_reply("Looks great, 9/10!", "correctness")
    assert f.score is None and f.readable is False


def test_fenced_and_prose_json_recovered():
    f = rt.parse_critic_reply('Sure:\n```json\n{"score": 7, "feedback": "ok"}\n```', "clarity")
    assert f.score == 7 and f.readable
    g = rt.parse_critic_reply('My view {"score": 4, "feedback": "bad", "suggestions": "fix"} end', "clarity")
    assert g.score == 4 and g.suggestions == ["fix"]


@pytest.mark.parametrize("raw,exp", [(0, 1), (-3, 1), (11, 10), (100, 10), (7.6, 8), ("9", 9)])
def test_scores_clamped(raw, exp):
    assert rt.parse_critic_reply(json.dumps({"score": raw}), "c").score == exp


@pytest.mark.parametrize("raw", [None, "high", float("nan")])
def test_non_numeric_scores_unreadable(raw):
    txt = json.dumps({"score": raw}) if raw == raw else '{"score": NaN}'
    assert rt.parse_critic_reply(txt, "c").readable is False


# ---- W2 validation ------------------------------------------------------

@pytest.mark.parametrize("bad", [-1, 6, 2.5, True, "2"])
def test_max_revisions_validated(bad):
    with pytest.raises(ValueError):
        make(max_revisions=bad)


def test_protocol_validated():
    with pytest.raises(ValueError):
        make(protocol="yolo")


# ---- W3 architect -------------------------------------------------------

def test_default_architect_asks_for_no_json_plan():
    FakeClient.script = {"Architect": lambda p, n: "draft", "critic": crit(9), "Integrator": lambda p, n: "final"}
    c = make()
    run(c)
    a_prompt = c.client.calls[0][1]
    assert "---DRAFT---" not in a_prompt and "JSON" not in a_prompt


def test_legacy_plan_mode_still_parses_plan():
    plan = json.dumps({"summary": "s", "approach": "a", "concerns": ["c"]})
    FakeClient.script = {"Architect": lambda p, n: plan + "\n---DRAFT---\nthe draft",
                         "critic": crit(9), "Integrator": lambda p, n: "final"}
    r = run(make(architect_plan=True))
    assert r.trace.architect_plan.concerns == ["c"] and r.trace.rounds[0].draft == "the draft"


# ---- W4 gate --------------------------------------------------------------

def test_unreadable_critics_cannot_approve():
    FakeClient.script = {"Architect": lambda p, n: "d", "critic": lambda p, n: "no json here",
                         "Integrator": lambda p, n: f"rev{n}"}
    r = run(make(max_revisions=2))
    assert r.trace.approved is False and r.trace.revisions == 2
    assert r.trace.unreadable_critic_replies == 15
    assert all(rd.mean_score is None for rd in r.trace.rounds)


def test_low_correctness_blocks_exit_even_with_high_mean():
    def critic(p, n):
        s = 3 if p.startswith("You are the Correctness Critic") else 10
        return json.dumps({"score": s, "feedback": "f"})
    FakeClient.script = {"Architect": lambda p, n: "d", "critic": critic, "Integrator": lambda p, n: "x"}
    strict = run(make(max_revisions=1))
    assert strict.trace.rounds[0].mean_score == pytest.approx(8.6)
    assert strict.trace.approved is False and strict.trace.revisions == 1
    loose = run(make(max_revisions=1, strict_gate=False))
    assert loose.trace.approved is True and loose.trace.revisions == 0


def test_all_nines_exits_early_with_one_final_call():
    FakeClient.script = {"Architect": lambda p, n: "d", "critic": crit(9), "Integrator": lambda p, n: "final"}
    c = make()
    r = run(c)
    roles = [x[0] for x in c.client.calls]
    assert r.trace.approved and r.trace.revisions == 0 and roles.count("Integrator") == 1
    assert len(c.client.calls) == 7


def test_call_budget_bounded():
    FakeClient.script = {"Architect": lambda p, n: "d", "critic": crit(2), "Integrator": lambda p, n: "x"}
    c = make(max_revisions=5)
    run(c)
    assert len(c.client.calls) == 1 + 6 * 5 + 5 + 1


# ---- W5 answer preservation --------------------------------------------

def test_preserve_instruction_present_and_switchable():
    FakeClient.script = {"Architect": lambda p, n: "d", "critic": crit(9), "Integrator": lambda p, n: "x"}
    c = make()
    run(c)
    assert "must never change the answer" in c.client.calls[-1][1]
    c2 = make(preserve_answer=False)
    run(c2)
    assert "must never change the answer" not in c2.client.calls[-1][1]


# ---- W6 verifier ----------------------------------------------------------

def test_failing_verifier_blocks_exit_and_evidence_reaches_everyone():
    FakeClient.script = {"Architect": lambda p, n: "d", "critic": crit(10), "Integrator": lambda p, n: "x"}
    c = make(max_revisions=1, verifier=lambda t, d: (False, "ran code: got 4, draft says 5"))
    r = run(c)
    assert r.trace.approved is False and r.trace.revisions == 1
    assert all("got 4, draft says 5" in p for _, p in c.client.calls[1:])


def test_broken_verifier_is_not_trusted():
    def boom(t, d):
        raise RuntimeError("x")
    FakeClient.script = {"Architect": lambda p, n: "d", "critic": crit(9), "Integrator": lambda p, n: "x"}
    r = run(make(verifier=boom))
    assert r.trace.rounds[0].verifier_ok is None
    assert "verifier error" in r.trace.rounds[0].verifier_evidence


# ---- W7 resilience and trace ------------------------------------------

def test_critic_exception_recorded_not_fatal():
    def critic(p, n):
        if p.startswith("You are the Security Critic"):
            return TimeoutError("slow")
        return json.dumps({"score": 9})
    FakeClient.script = {"Architect": lambda p, n: "d", "critic": critic, "Integrator": lambda p, n: "x"}
    r = run(make())
    sec = [f for f in r.trace.critic_feedbacks if f.perspective == "security"][0]
    assert sec.readable is False and "TimeoutError" in sec.feedback
    assert r.trace.approved is True  # 4 readable 9s still clear the strict gate


def test_every_round_kept_in_trace():
    FakeClient.script = {"Architect": lambda p, n: "d0", "critic": lambda p, n: json.dumps({"score": 5}),
                         "Integrator": lambda p, n: f"d{n + 1}"}
    r = run(make(max_revisions=2))
    assert [rd.draft for rd in r.trace.rounds] == ["d0", "d1", "d2"]


def test_trace_json_backward_compatible_fields():
    FakeClient.script = {"Architect": lambda p, n: "d", "critic": crit(9), "Integrator": lambda p, n: "x"}
    d = json.loads(run(make()).trace.model_dump_json())
    for k in ("task", "protocol", "architect_plan", "critic_feedbacks", "revisions", "final_text"):
        assert k in d
