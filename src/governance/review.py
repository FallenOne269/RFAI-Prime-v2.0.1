"""Human review. A ``review`` decision only resolves through named people, never silently.

Rules enforced here:
- a reviewer name, role and written rationale are required;
- only roles listed in the result's required approvals can approve (if none are listed, any
  named reviewer can);
- approval completes only when every required role has approved;
- one rejection rejects the run;
- ``deny`` cannot be approved through review. Overriding a deny is out of scope for this
  runtime and needs the operator's own documented override process.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, field_validator

Disposition = Literal["approve", "reject"]
Outcome = Literal["allowed", "pending_review", "approved_after_review", "rejected", "denied"]


class ReviewError(ValueError):
    pass


class ReviewRecord(BaseModel):
    reviewer: str
    role: str
    disposition: Disposition
    rationale: str
    ts: Optional[str] = None

    @field_validator("reviewer", "role", "rationale")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be empty")
        return v.strip()


def outcome_of(decision: str, required: list[str], reviews: list[ReviewRecord]) -> Outcome:
    if decision == "deny":
        return "denied"
    if decision == "allow":
        return "allowed"
    if any(r.disposition == "reject" for r in reviews):
        return "rejected"
    approved_roles = {r.role for r in reviews if r.disposition == "approve"}
    if required:
        return "approved_after_review" if set(required) <= approved_roles else "pending_review"
    return "approved_after_review" if approved_roles else "pending_review"


def apply_review(result, record: ReviewRecord):
    """Add a review to a GovernedResult, log it, and recompute the outcome. Returns the result."""
    if result.guard.decision == "deny":
        raise ReviewError("a deny decision cannot be approved or rejected through review")
    if result.guard.decision == "allow":
        raise ReviewError("this run did not require review")
    if result.outcome in ("rejected",):
        raise ReviewError("this run was already rejected")
    required = result.guard.required_approvals
    if record.disposition == "approve" and required and record.role not in required:
        raise ReviewError(f"role {record.role!r} is not one of the required approvals {required}")
    if record.ts is None:
        record = record.model_copy(update={"ts": result.evidence.clock()})
    result.reviews.append(record)
    result.outcome = outcome_of(result.guard.decision, required, result.reviews)
    result.evidence.append("human_review", {**record.model_dump(), "outcome_after": result.outcome})
    return result
