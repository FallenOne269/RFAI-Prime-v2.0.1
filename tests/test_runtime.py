import json
from types import SimpleNamespace

import pytest

from src.rfai_prime_runtime import (
    CRITIC_PERSPECTIVES,
    EARLY_EXIT_SCORE,
    RFAIPrimeCouncil,
)

PLAN = {"summary": "s", "approach": "a", "concerns": ["c1"]}


class FakeMessages:
    """Stands in for anthropic.Anthropic().messages, routing by prompt role."""

    def __init__(self, critic_score=9, architect_text=None, critic_text=None):
        self.critic_score = critic_score
        self.architect_text = architect_text
        self.critic_text = critic_text
        self.calls = []

    def create(self, model, max_tokens, messages):
        prompt = messages[0]["content"]
        self.calls.append((model, prompt))
        if "You are the Architect" in prompt:
            text = self.architect_text or f"{json.dumps(PLAN)}\n---DRAFT---\ninitial draft"
        elif "Critic in the RFAI-PRIME council" in prompt:
            perspective = prompt.split("You are the ")[1].split(" Critic")[0].lower()
            text = self.critic_text or json.dumps({
                "perspective": perspective,
                "score": self.critic_score,
                "feedback": "ok",
                "suggestions": [],
            })
        else:
            text = f"integrated #{sum('Integrator' in p for _, p in self.calls)}"
        return SimpleNamespace(content=[SimpleNamespace(text=text)])

    def count(self, marker):
        return sum(marker in p for _, p in self.calls)


def make_council(messages, **kwargs):
    council = RFAIPrimeCouncil(api_key="test-key", **kwargs)
    council.client = SimpleNamespace(messages=messages)
    return council


async def test_architect_parses_plan_and_draft():
    council = make_council(FakeMessages())
    plan, draft = await council._architect("task")
    assert plan.model_dump() == PLAN
    assert draft == "initial draft"


async def test_architect_falls_back_on_invalid_json():
    council = make_council(FakeMessages(architect_text="not json at all"))
    plan, draft = await council._architect("my task")
    assert plan.summary == "my task"
    assert plan.approach == "not json at all"
    assert plan.concerns == []
    assert draft == "not json at all"


async def test_critic_falls_back_to_neutral_score():
    council = make_council(FakeMessages(critic_text="unstructured critique"))
    fb = await council._critic("task", "draft", "security")
    assert fb.perspective == "security"
    assert fb.score == 5
    assert fb.feedback == "unstructured critique"


async def test_invoke_exits_early_when_critics_are_satisfied():
    messages = FakeMessages(critic_score=int(EARLY_EXIT_SCORE) + 1)
    council = make_council(messages, protocol="execute", max_revisions=2)
    resp = await council.invoke("task")

    assert resp.trace.revisions == 0
    assert resp.trace.protocol == "execute"
    assert [f.perspective for f in resp.trace.critic_feedbacks] == CRITIC_PERSPECTIVES
    assert messages.count("You are the Architect") == 1
    assert messages.count("Critic in the RFAI-PRIME council") == len(CRITIC_PERSPECTIVES)
    assert messages.count("You are the Integrator") == 1
    assert resp.final_text == resp.trace.final_text == "integrated #1"


@pytest.mark.parametrize("max_revisions", [0, 1, 3])
async def test_invoke_revises_until_budget_exhausted(max_revisions):
    messages = FakeMessages(critic_score=3)
    council = make_council(messages, max_revisions=max_revisions)
    resp = await council.invoke("task")

    assert resp.trace.revisions == max_revisions
    rounds = max_revisions + 1
    assert messages.count("Critic in the RFAI-PRIME council") == rounds * len(CRITIC_PERSPECTIVES)
    assert messages.count("You are the Integrator") == max_revisions + 1


async def test_models_are_routed_per_role():
    messages = FakeMessages()
    council = make_council(
        messages, architect_model="arch", critic_model="crit", integrator_model="integ"
    )
    await council.invoke("task")
    models = {m for m, _ in messages.calls}
    assert models == {"arch", "crit", "integ"}


def test_from_env_reads_model_overrides(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")
    monkeypatch.setenv("RFAI_ARCHITECT_MODEL", "a-model")
    monkeypatch.setenv("RFAI_CRITIC_MODEL", "c-model")
    monkeypatch.setenv("RFAI_INTEGRATOR_MODEL", "i-model")
    council = RFAIPrimeCouncil.from_env(protocol="execute", max_revisions=4)
    assert (council.architect_model, council.critic_model, council.integrator_model) == (
        "a-model", "c-model", "i-model",
    )
    assert council.protocol == "execute"
    assert council.max_revisions == 4
