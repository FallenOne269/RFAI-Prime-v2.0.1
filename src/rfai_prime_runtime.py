"""
RFAI-PRIME v2.0.1 Council Runtime

Architecture: Architect → parallel Critics (x5) → Integrator
Protocols   : plan | execute
"""

import asyncio
import os
import sys
import argparse
from typing import Literal, Optional

import anthropic
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_ARCHITECT_MODEL  = "claude-opus-4-6"
DEFAULT_CRITIC_MODEL     = "claude-sonnet-4-6"
DEFAULT_INTEGRATOR_MODEL = "claude-opus-4-6"

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
    score: int          # 1–10
    feedback: str
    suggestions: list[str]


class CouncilTrace(BaseModel):
    task: str
    protocol: str
    architect_plan: ArchitectPlan
    critic_feedbacks: list[CriticFeedback]
    revisions: int
    final_text: str


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
    ) -> None:
        self.client           = anthropic.Anthropic(api_key=api_key or os.environ["ANTHROPIC_API_KEY"])
        self.architect_model  = architect_model
        self.critic_model     = critic_model
        self.integrator_model = integrator_model
        self.protocol         = protocol
        self.max_revisions    = max_revisions

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

    async def _critic(self, task: str, draft: str, perspective: str) -> CriticFeedback:
        prompt = (
            f"You are the {perspective.title()} Critic in the RFAI-PRIME council.\n"
            f"Task: {task}\n\n"
            f"Draft response:\n{draft}\n\n"
            f"Evaluate strictly from a {perspective} perspective. "
            "Respond with a JSON object:\n"
            f'{{"perspective": "{perspective}", "score": <1-10>, '
            '"feedback": "...", "suggestions": ["..."]}}'
        )
        resp = await asyncio.to_thread(
            self.client.messages.create,
            model=self.critic_model,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        try:
            return CriticFeedback.model_validate_json(resp.content[0].text.strip())
        except Exception:
            return CriticFeedback(
                perspective=perspective,
                score=5,
                feedback=resp.content[0].text.strip(),
                suggestions=[],
            )

    async def _integrator(
        self, task: str, draft: str, feedbacks: list[CriticFeedback]
    ) -> str:
        feedback_block = "\n".join(
            f"- [{f.perspective.upper()}] score={f.score}: {f.feedback}\n"
            f"  suggestions: {f.suggestions}"
            for f in feedbacks
        )
        prompt = (
            f"You are the Integrator in the RFAI-PRIME council.\n"
            f"Task: {task}\n\n"
            f"Architect draft:\n{draft}\n\n"
            f"Council feedback:\n{feedback_block}\n\n"
            "Produce the final, polished response that incorporates all valid feedback."
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

    async def invoke(self, task: str) -> CouncilResponse:
        """Run the full council pipeline on *task* and return a CouncilResponse."""
        plan, draft = await self._architect(task)
        all_feedbacks: list[CriticFeedback] = []
        revisions = 0

        for _ in range(self.max_revisions + 1):
            feedbacks = await asyncio.gather(
                *[self._critic(task, draft, p) for p in CRITIC_PERSPECTIVES]
            )
            all_feedbacks = list(feedbacks)
            avg_score = sum(f.score for f in all_feedbacks) / len(all_feedbacks)
            if avg_score >= 8.0 or revisions >= self.max_revisions:
                break
            draft = await self._integrator(task, draft, all_feedbacks)
            revisions += 1

        final = await self._integrator(task, draft, all_feedbacks)
        trace = CouncilTrace(
            task=task,
            protocol=self.protocol,
            architect_plan=plan,
            critic_feedbacks=all_feedbacks,
            revisions=revisions,
            final_text=final,
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
    inv.add_argument("--json", action="store_true", dest="as_json",
                     help="Print the full trace as JSON instead of just final_text")

    args = parser.parse_args()

    if args.command == "invoke":
        task = args.task or sys.stdin.read().strip()
        council = RFAIPrimeCouncil.from_env(
            protocol=args.protocol,
            max_revisions=args.max_revisions,
        )
        resp = asyncio.run(council.invoke(task))
        if args.as_json:
            print(resp.trace.model_dump_json(indent=2))
        else:
            print(resp.final_text)
    else:
        parser.print_help()


if __name__ == "__main__":
    _cli()
