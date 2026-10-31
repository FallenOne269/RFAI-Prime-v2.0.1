"""Governance layer for the RFAI-Prime council (v2.1 candidate, local only).

What this package is: a policy screen (allow / review / deny with monotonic escalation),
execution budgets with a budget_exhausted state, a hash-chained evidence log that stores
hashes instead of raw text by default, and a human-review record.

What it is not: a classifier, a correctness check, or a certification. An ``allow`` means
no policy rule matched and the council raised no flag. It does not mean the answer is right.
"""

from .safety_guard import (  # noqa: F401
    DECISION_ORDER,
    GuardResult,
    Policy,
    PolicyError,
    Rule,
    SafetyGuard,
    escalate,
    load_policy,
)
from .budget import BudgetExhausted, ExecutionBudget, MeteredClient  # noqa: F401
from .evidence import EvidenceLog, content_ref, verify_chain  # noqa: F401
from .review import ReviewError, ReviewRecord, apply_review  # noqa: F401
from .runner import GovernedCouncil, GovernedResult, JobContext  # noqa: F401
