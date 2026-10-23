"""
RFAI-PRIME v2.0.2-candidate Council Runtime (NOT merged; built Oct 21 2026 for Saturday testing)

Architecture: Architect → parallel Critics (x5) → Integrator
Protocols   : plan | execute

Changes from v2.0.1, each behind a constructor flag so it can be ablated:
  W1  unreadable critic reply -> score None (excluded), never a silent 5; scores clamped 1-10;
      JSON is also recovered from code fences / surrounding prose.            (always on)
  W2  max_revisions validated to 0..MAX_REVISIONS_CEILING.                   (always on)
  W3  architect_plan=False: the Architect just answers. In v2.0.1 the JSON plan is
      never used downstream, and the format demand may hurt the draft.
  W4  strict_gate=True: early exit needs >= MIN_READABLE_CRITICS readable scores, a mean
      >= EARLY_EXIT_SCORE AND a correctness score >= EARLY_EXIT_SCORE.
  W5  preserve_answer=True: the Integrator keeps the draft's answer unless a critic names a
      specific, checkable error it can confirm; style feedback cannot flip the answer.
  W6  verifier: optional callable(task, draft) -> (ok: bool|None, evidence: str). Its evidence
      goes to critics and the Integrator, and ok=False blocks early exit (CRITIC-style
      external feedback). None = no verifier, same as v2.0.1.
  W7  trace keeps every round, the approval flag and the count of unreadable critic replies;
      a critic call that raises is recorded as unreadable instead of crashing the run.
"""

import asyncio
import json
import os
import re
import sys
import argparse
from typing import Callable, Literal, Optional

import anthropic
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_ARCHITECT_MODEL  = "claude-opus-4-6"
DEFAULT_CRITIC_MODEL     = "claude-sonnet-4-6"
DEFAULT_INTEGRATOR_MODEL = "claude-opus-4-6"

EARLY_EXIT_SCORE = 8.0
MAX_REVISIONS_CEILING = 5
MIN_READABLE_CRITICS = 3

CRITIC_PERSPECTIVES = [
    "correctness",
    "completeness",
    "security",
    "performance",
    "clarity",
]

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class ArchitectPlan(BaseModel):
    summary: str
    approach: str
    concerns: list[str]


class CriticFeedback(BaseModel):
    perspective: str
    score: Optional[int] = None   # 1–10, or None when the reply could not be read
    feedback: str = ""
    suggestions: list[str] = []
    readable: bool = True


class CouncilRound(BaseModel):
    draft: str
    feedbacks: list[CriticFeedback]
    mean_score: Optional[float]
    approved: bool
    verifier_ok: Optional[bool] = None
    verifier_evidence: str = ""


class CouncilTrace(BaseModel):
    task: str
    protocol: str
    architect_plan: ArchitectPlan
    critic_feedbacks: list[CriticFeedback]
    revisions: int
    final_text: str
    rounds: list[CouncilRound] = []
    approved: bool = False
    unreadable_critic_replies: int = 0


# ---------------------------------------------------------------------------
# Critic reply parsing (W1)
# ---------------------------------------------------------------------------


def _clamp_score(value) -> Optional[int]:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if f != f or f in (float("inf"), float("-inf")):
        return None
    return int(min(10, max(1, round(f))))


def parse_critic_reply(text: str, perspective: str) -> CriticFeedback:
    """Read a critic reply. Unreadable -> score None, readable False. Never invents a score."""
    raw = (text or "").strip()
    candidates = [raw]
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.S)
    if fence:
        candidates.append(fence.group(1))
    start, end = raw.find("{"), raw.rfind("}")
    if 0 <= start < end:
        candidates.append(raw[start:end + 1])
    for c in candidates:
        try:
            d = json.loads(c)
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        score = _clamp_score(d.get("score"))
        if score is None:
            continue
        sugg = d.get("suggestions") or []
        if not isinstance(sugg, list):
            sugg = [str(sugg)]
        return CriticFeedback(perspective=perspective, score=score,
                              feedback=str(d.get("feedback", "")),
                              suggestions=[str(s) for s in sugg], readable=True)
    return CriticFeedback(perspective=perspective, score=None, feedback=raw[:2000],
                          suggestions=[], readable=False)


class CouncilResponse(BaseModel):
    final_text: str
    trace: CouncilTrace


# ---------------------------------------------------------------------------
# Council
# ---------------------------------------------------------------------------


class RFAIPrimeCouncil:
    """Council of AI agents: Architect + 5 Critics + Integrator."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        architect_model: str = DEFAULT_ARCHITECT_MODEL,
        critic_model: str = DEFAULT_CRITIC_MODEL,
        integrator_model: str = DEFAULT_INTEGRATOR_MODEL,
        protocol: Literal["plan", "execute"] = "plan",
        max_revisions: int = 2,
        architect_plan: bool = False,
        strict_gate: bool = True,
        preserve_answer: bool = True,
        verifier: Optional[Callable[[str, str], tuple]] = None,
    ) -> None:
        if isinstance(max_revisions, bool) or not isinstance(max_revisions, int):
            raise ValueError("max_revisions must be an integer")
        if not 0 <= max_revisions <= MAX_REVISIONS_CEILING:
            raise ValueError(f"max_revisions must be between 0 and {MAX_REVISIONS_CEILING}")
        if protocol not in ("plan", "execute"):
            raise ValueError("protocol must be 'plan' or 'execute'")
        self.client           = anthropic.Anthropic(api_key=api_key or os.environ["ANTHROPIC_API_KEY"])
        self.architect_model  = architect_model
        self.critic_model     = critic_model
        self.integrator_model = integrator_model
        self.protocol         = protocol
        self.max_revisions    = max_revisions
        self.architect_plan   = architect_plan
        self.strict_gate      = strict_gate
        self.preserve_answer  = preserve_answer
        self.verifier         = verifier

    @classmethod
    def from_env(
        cls,
        protocol: str = "plan",
        max_revisions: int = 2,
    ) -> "RFAIPrimeCouncil":
        """Construct a council from environment variables."""
        return cls(
            api_key=os.environ.get("ANTHROPIC_API_KEY"),
            architect_model=os.environ.get("RFAI_ARCHITECT_MODEL",  DEFAULT_ARCHITECT_MODEL),
            critic_model=os.environ.get("RFAI_CRITIC_MODEL",        DEFAULT_CRITIC_MODEL),
            integrator_model=os.environ.get("RFAI_INTEGRATOR_MODEL", DEFAULT_INTEGRATOR_MODEL),
            protocol=protocol,
            max_revisions=max_revisions,
        )

    # ------------------------------------------------------------------
    # Internal agent calls (all run in a thread so asyncio loop is free)
    # ------------------------------------------------------------------

    async def _architect(self, task: str) -> tuple[ArchitectPlan, str]:
        if not self.architect_plan:  # W3: no unused JSON plan in front of the draft
            prompt = (
                f"You are the Architect in the RFAI-PRIME council.\n"
                f"Protocol: {self.protocol}\n"
                f"Task: {task}\n\n"
                "Write your full draft response to the task. Follow any answer format the task asks for."
            )
            resp = await asyncio.to_thread(
                self.client.messages.create,
                model=self.architect_model,
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}],
            )
            draft = resp.content[0].text.strip()
            return ArchitectPlan(summary=task, approach="(no separate plan requested)", concerns=[]), draft
        prompt = (
            f"You are the Architect in the RFAI-PRIME council.\n"
            f"Protocol: {self.protocol}\n"
            f"Task: {task}\n\n"
            "Respond with a JSON object matching:\n"
            '{"summary": "...", "approach": "...", "concerns": ["..."]}\n'
            "Then output a line containing only ---DRAFT--- followed by your full draft response."
        )
        resp = await asyncio.to_thread(
            self.client.messages.create,
            model=self.architect_model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        text = resp.content[0].text
        if "---DRAFT---" in text:
            plan_json, draft = text.split("---DRAFT---", 1)
        else:
            plan_json, draft = text, text
        try:
            plan = ArchitectPlan.model_validate_json(plan_json.strip())
        except Exception:
            plan = ArchitectPlan(summary=task, approach=plan_json.strip(), concerns=[])
        return plan, draft.strip()

    async def _critic(self, task: str, draft: str, perspective: str,
                      evidence: str = "") -> CriticFeedback:
        evidence_block = f"External check result:\n{evidence}\n\n" if evidence else ""
        prompt = (
            f"You are the {perspective.title()} Critic in the RFAI-PRIME council.\n"
            f"Task: {task}\n\n"
            f"Draft response:\n{draft}\n\n"
            f"{evidence_block}"
            f"Evaluate strictly from a {perspective} perspective. "
            "Respond with a JSON object:\n"
            f'{{"perspective": "{perspective}", "score": <1-10>, '
            '"feedback": "...", "suggestions": ["..."]}}'
        )
        try:
            resp = await asyncio.to_thread(
                self.client.messages.create,
                model=self.critic_model,
                max_tokens=512,
                messages=[{"role": "user", "content": prompt}],
            )
            text = resp.content[0].text
        except Exception as e:  # W7: one failed critic is recorded, not fatal
            return CriticFeedback(perspective=perspective, score=None,
                                  feedback=f"critic call failed: {type(e).__name__}",
                                  suggestions=[], readable=False)
        return parse_critic_reply(text, perspective)

    async def _integrator(
        self, task: str, draft: str, feedbacks: list[CriticFeedback], evidence: str = ""
    ) -> str:
        feedback_block = "\n".join(
            f"- [{f.perspective.upper()}] score={f.score if f.readable else 'unreadable'}: {f.feedback}\n"
            f"  suggestions: {f.suggestions}"
            for f in feedbacks
        )
        evidence_block = f"External check result:\n{evidence}\n\n" if evidence else ""
        instruction = "Produce the final, polished response that incorporates all valid feedback."
        if self.preserve_answer:  # W5
            instruction += (
                " Keep the draft's conclusions and final answer unless a critic or the external check "
                "names a specific, checkable error that you confirm yourself by re-working it. "
                "Feedback about style, length or clarity must never change the answer. "
                "Keep any answer format the task requires."
            )
        prompt = (
            f"You are the Integrator in the RFAI-PRIME council.\n"
            f"Task: {task}\n\n"
            f"Architect draft:\n{draft}\n\n"
            f"Council feedback:\n{feedback_block}\n\n"
            f"{evidence_block}"
            f"{instruction}"
        )
        resp = await asyncio.to_thread(
            self.client.messages.create,
            model=self.integrator_model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text.strip()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def _approved(self, feedbacks: list[CriticFeedback], verifier_ok: Optional[bool]) -> tuple[bool, Optional[float]]:
        readable = [f.score for f in feedbacks if f.readable and f.score is not None]
        mean = sum(readable) / len(readable) if readable else None
        if verifier_ok is False:
            return False, mean
        if not self.strict_gate:
            # v2.0.1 rule, minus the fake 5s: mean of readable scores
            return (mean is not None and mean >= EARLY_EXIT_SCORE), mean
        corr = next((f.score for f in feedbacks
                     if f.perspective == "correctness" and f.readable), None)
        ok = (len(readable) >= MIN_READABLE_CRITICS and mean is not None
              and mean >= EARLY_EXIT_SCORE and corr is not None and corr >= EARLY_EXIT_SCORE)
        return ok, mean

    def _verify(self, task: str, draft: str) -> tuple[Optional[bool], str]:
        if self.verifier is None:
            return None, ""
        try:
            ok, evidence = self.verifier(task, draft)
            return (None if ok is None else bool(ok)), str(evidence)[:4000]
        except Exception as e:  # a broken verifier is reported, never trusted
            return None, f"verifier error: {type(e).__name__}"

    async def invoke(self, task: str) -> CouncilResponse:
        """Run the full council pipeline on *task* and return a CouncilResponse."""
        plan, draft = await self._architect(task)
        all_feedbacks: list[CriticFeedback] = []
        rounds: list[CouncilRound] = []
        revisions = 0
        approved = False
        evidence = ""
        unreadable = 0

        for _ in range(self.max_revisions + 1):
            v_ok, evidence = self._verify(task, draft)
            feedbacks = await asyncio.gather(
                *[self._critic(task, draft, p, evidence) for p in CRITIC_PERSPECTIVES]
            )
            all_feedbacks = list(feedbacks)
            unreadable += sum(1 for f in all_feedbacks if not f.readable)
            approved, mean = self._approved(all_feedbacks, v_ok)
            rounds.append(CouncilRound(draft=draft, feedbacks=all_feedbacks, mean_score=mean,
                                       approved=approved, verifier_ok=v_ok,
                                       verifier_evidence=evidence))
            if approved or revisions >= self.max_revisions:
                break
            draft = await self._integrator(task, draft, all_feedbacks, evidence)
            revisions += 1

        final = await self._integrator(task, draft, all_feedbacks, evidence)
        trace = CouncilTrace(
            task=task,
            protocol=self.protocol,
            architect_plan=plan,
            critic_feedbacks=all_feedbacks,
            revisions=revisions,
            final_text=final,
            rounds=rounds,
            approved=approved,
            unreadable_critic_replies=unreadable,
        )
        return CouncilResponse(final_text=final, trace=trace)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cli() -> None:
    parser = argparse.ArgumentParser(
        prog="rfai_prime_runtime",
        description="RFAI-PRIME v2.0.1 council runtime",
    )
    sub = parser.add_subparsers(dest="command")

    inv = sub.add_parser("invoke", help="Run the council on a task")
    inv.add_argument("task", nargs="?", help="Task text (reads stdin if omitted)")
    inv.add_argument("--protocol", default="plan", choices=["plan", "execute"])
    inv.add_argument("--max-revisions", type=int, default=2)
    inv.add_argument("--legacy-plan", action="store_true", help="v2.0.1 JSON plan before the draft")
    inv.add_argument("--loose-gate", action="store_true", help="mean-only early exit")
    inv.add_argument("--no-preserve-answer", action="store_true")
    inv.add_argument("--json", action="store_true", dest="as_json",
                     help="Print the full trace as JSON instead of just final_text")

    args = parser.parse_args()

    if args.command == "invoke":
        task = args.task or sys.stdin.read().strip()
        council = RFAIPrimeCouncil.from_env(
            protocol=args.protocol,
            max_revisions=args.max_revisions,
        )
        council.architect_plan = args.legacy_plan
        council.strict_gate = not args.loose_gate
        council.preserve_answer = not args.no_preserve_answer
        resp = asyncio.run(council.invoke(task))
        if args.as_json:
            print(resp.trace.model_dump_json(indent=2))
        else:
            print(resp.final_text)
    else:
        parser.print_help()


if __name__ == "__main__":
    _cli()
