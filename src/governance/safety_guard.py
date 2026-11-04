"""SafetyGuard: a versioned, rule-based policy screen with monotonic escalation.

Decisions are ordered allow < review < deny. Combining two results always keeps the
stricter decision, the higher risk, and the union of reasons and required approvals,
so a later permissive result can never downgrade an earlier review or deny.

The rules are regular expressions and declared-capability checks. They are a keyword
screen that a reviewer can read and audit, not a learned classifier, and they will miss
anything phrased in a way the patterns do not cover.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable, Literal, Optional

from pydantic import BaseModel, Field

Decision = Literal["allow", "review", "deny"]
Risk = Literal["none", "low", "medium", "high", "critical"]
Stage = Literal["input", "output", "both"]

DECISION_ORDER = {"allow": 0, "review": 1, "deny": 2}
RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class PolicyError(ValueError):
    """A policy file that cannot be trusted to load."""


class Rule(BaseModel):
    id: str
    description: str
    stage: Stage = "input"
    decision: Literal["review", "deny"]
    risk: Risk = "medium"
    reason_code: str
    patterns: list[str] = Field(default_factory=list)       # any regex match triggers
    capabilities: list[str] = Field(default_factory=list)   # any declared capability triggers
    domains: list[str] = Field(default_factory=list)        # any declared use domain triggers
    unless_flags: list[str] = Field(default_factory=list)   # rule skipped if all these flags are set
    when_flags: list[str] = Field(default_factory=list)     # rule applies only if all these flags are set
    required_approvals: list[str] = Field(default_factory=list)


class Policy(BaseModel):
    policy_id: str
    version: str
    description: str = ""
    rules: list[Rule]

    def canonical_json(self) -> str:
        return json.dumps(self.model_dump(), sort_keys=True, separators=(",", ":"))

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()


class GuardResult(BaseModel):
    decision: Decision = "allow"
    risk: Risk = "none"
    reasons: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    required_approvals: list[str] = Field(default_factory=list)
    policy_id: str = ""
    policy_version: str = ""
    policy_sha256: str = ""
    stages: list[str] = Field(default_factory=list)


def _union(a: Iterable[str], b: Iterable[str]) -> list[str]:
    out: list[str] = []
    for x in list(a) + list(b):
        if x not in out:
            out.append(x)
    return out


def escalate(prev: GuardResult, new: GuardResult) -> GuardResult:
    """Combine two results. Never less strict than either input."""
    decision = prev.decision if DECISION_ORDER[prev.decision] >= DECISION_ORDER[new.decision] else new.decision
    risk = prev.risk if RISK_ORDER[prev.risk] >= RISK_ORDER[new.risk] else new.risk
    return GuardResult(
        decision=decision,
        risk=risk,
        reasons=_union(prev.reasons, new.reasons),
        reason_codes=_union(prev.reason_codes, new.reason_codes),
        matched_rules=_union(prev.matched_rules, new.matched_rules),
        required_approvals=_union(prev.required_approvals, new.required_approvals),
        policy_id=prev.policy_id or new.policy_id,
        policy_version=prev.policy_version or new.policy_version,
        policy_sha256=prev.policy_sha256 or new.policy_sha256,
        stages=_union(prev.stages, new.stages),
    )


def flag(decision: Decision, risk: Risk, reason_code: str, reason: str,
         approvals: Optional[list[str]] = None, stage: str = "runtime") -> GuardResult:
    """A result raised by the runner itself (budget, errors, council signals), not a policy rule."""
    return GuardResult(decision=decision, risk=risk, reasons=[reason], reason_codes=[reason_code],
                       required_approvals=list(approvals or []), stages=[stage])


def validate_policy(policy: Policy) -> dict[str, list[re.Pattern]]:
    """Check a policy and compile its patterns. Raises PolicyError on anything doubtful."""
    if not policy.policy_id.strip() or not policy.version.strip():
        raise PolicyError("policy_id and version are required")
    seen: set[str] = set()
    compiled: dict[str, list[re.Pattern]] = {}
    for r in policy.rules:
        if r.id in seen:
            raise PolicyError(f"duplicate rule id {r.id!r}")
        seen.add(r.id)
        if not (r.patterns or r.capabilities or r.domains):
            raise PolicyError(f"rule {r.id!r} has no trigger (patterns, capabilities or domains)")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", r.reason_code):
            raise PolicyError(f"rule {r.id!r}: reason_code must be UPPER_SNAKE_CASE")
        try:
            compiled[r.id] = [re.compile(p, re.I) for p in r.patterns]
        except re.error as e:
            raise PolicyError(f"rule {r.id!r}: bad pattern: {e}") from e
    return compiled


def load_policy(path: str | Path) -> Policy:
    try:
        data = json.loads(Path(path).read_text())
        policy = Policy.model_validate(data)
    except PolicyError:
        raise
    except Exception as e:
        raise PolicyError(f"cannot load policy {path}: {e}") from e
    validate_policy(policy)
    return policy


class SafetyGuard:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self._compiled = validate_policy(policy)

    def _base(self) -> GuardResult:
        return GuardResult(policy_id=self.policy.policy_id, policy_version=self.policy.version,
                           policy_sha256=self.policy.sha256)

    def evaluate(self, text: str, stage: Literal["input", "output"],
                 capabilities: Iterable[str] = (), domain: Optional[str] = None,
                 flags: Iterable[str] = ()) -> GuardResult:
        caps, flags = set(capabilities), set(flags)
        result = self._base()
        result.stages = [stage]
        for r in self.policy.rules:
            if r.stage not in (stage, "both"):
                continue
            if r.when_flags and not set(r.when_flags) <= flags:
                continue
            if r.unless_flags and set(r.unless_flags) <= flags:
                continue
            why = None
            for pat in self._compiled[r.id]:
                if pat.search(text or ""):
                    why = f"{r.description} (pattern matched in {stage})"
                    break
            if why is None and caps & set(r.capabilities):
                why = f"{r.description} (capability declared: {', '.join(sorted(caps & set(r.capabilities)))})"
            if why is None and domain and domain in r.domains:
                why = f"{r.description} (declared domain: {domain})"
            if why is None:
                continue
            hit = GuardResult(decision=r.decision, risk=r.risk, reasons=[why],
                              reason_codes=[r.reason_code], matched_rules=[r.id],
                              required_approvals=r.required_approvals, stages=[stage])
            result = escalate(result, hit)
        return result
