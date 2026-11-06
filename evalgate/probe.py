"""Observation probe. Runs INSIDE an isolated child process against one version.

The gate copies only the version's ``src/`` and ``policies/`` into a fresh
temporary directory, copies this file next to it, and starts
``python -I probe.py <version_dir> <request.json> <observations.json>`` with a
stripped environment. The request holds case inputs only. Expected answers,
thresholds and scoring never enter this process: the parent gate scores the
raw observations itself.

The probe owns its model stand-in (``ProbeClient``) and its clock, so a
candidate cannot swap in a friendlier script, and the number of model calls
is counted here rather than taken from the candidate's own usage meter.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Dict, List

DECISIONS = ("allow", "review", "deny")


@dataclass
class _Block:
    text: str


class _Reply:
    def __init__(self, text: str) -> None:
        self.content = [_Block(text)]
        self.usage = None


class ProbeClient:
    """Gate-owned scripted model. Role is read from the prompt header."""

    def __init__(self, script: Dict[str, Any]) -> None:
        self.script = script
        self.calls = 0
        self.messages = self

    def create(self, model: str = "", max_tokens: int = 0, messages: Any = None, **_: Any) -> _Reply:
        self.calls += 1
        if self.script.get("down"):
            raise ConnectionError("probe: scripted model outage")
        prompt = messages[0]["content"] if messages else ""
        head = prompt[:300]
        critic = re.search(r"You are the (\w+) Critic", head)
        if critic:
            score = self.script.get("critic", 9)
            if score == "unreadable":
                return _Reply("Looks fine overall, maybe a 9 out of 10.")
            return _Reply(json.dumps({
                "perspective": critic.group(1).lower(),
                "score": score,
                "feedback": "probe feedback",
                "suggestions": [],
            }))
        if "Integrator" in head:
            return _Reply(self.script.get("final", self.script.get("draft", "")))
        return _Reply(self.script.get("draft", ""))


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def wall(self) -> str:
        return "2026-01-01T00:00:00Z"

    def mono(self) -> float:
        self.t += 0.001
        return self.t


def main() -> None:
    version_dir, request_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(request_path, encoding="utf-8") as fh:
        request = json.load(fh)
    out: Dict[str, Any] = {"results": {}}
    sys.path.insert(0, version_dir)
    try:
        from src.governance import budget as bud  # noqa: E402
        from src.governance import review as rev  # noqa: E402
        from src.governance import runner  # noqa: E402
        from src.governance import safety_guard as sg  # noqa: E402

        policy = sg.load_policy(os.path.join(version_dir, request["policy_path"]))
        guard = sg.SafetyGuard(policy)
        out["policy_sha256"] = getattr(policy, "sha256", None)
    except Exception as exc:  # the version could not even be loaded
        out["fatal"] = f"{type(exc).__name__}: {exc}"
        _write(out_path, out)
        return

    def op_guard(inp: Dict[str, Any]) -> Dict[str, Any]:
        r = guard.evaluate(
            inp["text"], stage=inp["stage"],
            capabilities=inp.get("capabilities", []),
            domain=inp.get("domain"), flags=inp.get("flags", []),
        )
        return {"decision": r.decision, "risk": r.risk, "reason_codes": list(r.reason_codes)}

    def op_escalate_matrix(inp: Dict[str, Any]) -> Dict[str, Any]:
        matrix = {}
        for a in DECISIONS:
            for b in DECISIONS:
                prev = sg.GuardResult(decision=a, risk="low")
                new = sg.GuardResult(decision=b, risk="low")
                matrix[f"{a}+{b}"] = sg.escalate(prev, new).decision
        return {"matrix": matrix}

    def op_run(inp: Dict[str, Any]) -> Dict[str, Any]:
        client = ProbeClient(inp["script"])
        clock = _Clock()
        council = runner.GovernedCouncil(
            client, guard,
            budget=bud.ExecutionBudget(**inp.get("budget", {})),
            council_factory=runner.default_council_factory(max_revisions=inp.get("max_revisions", 1)),
            clock=clock.wall, monotonic=clock.mono,
        )
        ctx = runner.JobContext(job_id="probe", **inp.get("context", {}))
        res = asyncio.run(council.run(inp["task"], ctx, run_id="probe-run"))
        try:
            res.release_text()
            releasable = True
        except PermissionError:
            releasable = False
        obs: Dict[str, Any] = {
            "status": res.status,
            "decision": res.guard.decision,
            "outcome": res.outcome,
            "reason_codes": list(res.guard.reason_codes),
            "required_approvals": list(res.guard.required_approvals),
            "withheld": res.withheld,
            "final_text": res.final_text,
            "releasable": releasable,
            "client_calls": client.calls,
            "events": res.evidence.events,
        }
        reviews: List[Dict[str, Any]] = []
        for r in inp.get("reviews", []):
            try:
                rev.apply_review(res, rev.ReviewRecord(**r))
                reviews.append({"accepted": True, "outcome": res.outcome})
            except Exception as exc:
                reviews.append({"accepted": False, "error": type(exc).__name__, "outcome": res.outcome})
        obs["reviews"] = reviews
        return obs

    ops = {"guard": op_guard, "run": op_run, "escalate_matrix": op_escalate_matrix}
    for case in request["cases"]:
        try:
            obs = ops[case["op"]](case["input"])
            out["results"][case["id"]] = {"ok": True, "obs": json.loads(json.dumps(obs, default=str))}
        except Exception as exc:
            out["results"][case["id"]] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    _write(out_path, out)


def _write(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


if __name__ == "__main__":
    main()
