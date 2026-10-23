# RFAI-Prime governance layer (v2.1 candidate)

This layer wraps the council so a supervised Discovery engagement can show, in front of a client, what the system blocks, what it sends to a person, what it spends, and what it recorded. It does not make the council's answers more accurate, and nothing here should be sold as an accuracy or compliance claim.

Status: local candidate on branch `rfai-v2.1-governed-candidate`. Not pushed, not deployed, not run on Claude.

## What is implemented and tested

| Control | Where | What it does |
|---|---|---|
| SafetyGuard | `src/governance/safety_guard.py` | Versioned JSON policy; each rule gives `review` or `deny` with a risk level, reason code and required approvals. Policy is validated on load and hashed. |
| Monotonic escalation | `escalate()` | Combining results keeps the stricter decision (allow < review < deny), the higher risk and every reason. Nothing later can downgrade it. |
| Input screen | runner step 1 | A `deny` at input stops the run before any model call. Oversized input is denied. |
| Output screen | runner step 3 | A `deny` on the output withholds the text; only its hash is logged. |
| Execution budget | `src/governance/budget.py` | Caps on model calls, prompt size, reply size and wall-clock time. A spent budget ends in `budget_exhausted` and goes to the operator. |
| Fail-safe errors | runner step 2 | Provider outages and other errors become `review`, never `allow`. |
| Council signals | runner step 2 | Unresolved critics, too many unreadable critic replies, a failed external check, or a truncated reply each add a `review`. Council approval never removes one. |
| Evidence log | `src/governance/evidence.py` | Append-only, SHA-256 hash-chained events: configuration (code hashes, policy version and hash, budget, council switches), both screens, every council round, usage, decision and reviews. |
| Content minimisation | `content_ref()` | Default `hash_only` stores hashes and lengths, not text. `redacted` keeps a masked excerpt. `raw` is opt-in. |
| Human review | `src/governance/review.py` | Named reviewer, role and rationale required. Every required role must approve. One rejection is final. A `deny` cannot be approved through review. `release_text()` refuses until the outcome allows it. |
| Model adapters | `src/governance/adapters.py` | Scripted client for offline demos and tests; OpenAI-compatible client for a local model, loopback-only by default. |
| Acceptance suite | `scenarios/discovery_acceptance_v1.json`, `python -m src.governance.discovery_demo` | 15 scenarios (normal, boundary, prohibited, prompt injection, leakage, provider outage, budget, unreadable critics, reviewer escalation, high-impact domains, personal data). Writes `evidence_pack.json` and `acceptance_report.md`. Reproducible byte for byte with the default fixed clock. |

## Default policy (`policies/discovery_default_v1.json`, v1.0.0)

- Deny: credentials or private keys in the input or output; jailbreak, cyber or dual-use testing without a `written_testing_authorization` flag; weapons or malware requests; high-impact domains flagged `unreviewed_production`.
- Review: personal data (email, US SSN, phone) unless `personal_data_authorized`; prompt-injection phrasing; high-impact domains (employment, education, credit, essential services, justice, biometrics, migration, health, safety), needing a domain expert and a risk owner; outputs that claim guarantees or certifications.

The rules are regular expressions and declared capabilities. They are easy to read and audit, and easy to get around with wording they do not cover. Tailor them per client; every change produces a new policy hash in the evidence.

## How to run

```bash
pip install pydantic pytest          # add anthropic to run on Claude
python -m pytest -q tests                      # 87 tests, scripted replies, no key, no network
python -m src.governance.discovery_demo        # offline acceptance run -> evidence_out/
python -m src.governance.discovery_demo --backend local --max-revisions 0 \
    --url http://127.0.0.1:8080/v1/chat/completions   # a local model, e.g. llama-server
```

In code:

```python
from src.governance import GovernedCouncil, SafetyGuard, ExecutionBudget, JobContext, load_policy
from src.governance import ReviewRecord, apply_review

gc = GovernedCouncil(client, SafetyGuard(load_policy("policies/discovery_default_v1.json")),
                     budget=ExecutionBudget(max_model_calls=19, max_wall_seconds=300))
res = await gc.run(task, JobContext(job_id="acme-001", declared_domain=None))
res.guard.decision, res.outcome, res.guard.reason_codes
res.evidence.to_json()          # export; keep res.evidence.head somewhere separate
```

`client` is anything with `.messages.create(model, max_tokens, messages)`: the anthropic SDK client, `OpenAICompatClient`, or `ScriptedClient`.

## Known limits

- `allow` means no rule matched and no council flag was raised. It is not a correctness signal. On the local small model, the council scored below a single plain call (17 vs 22 of 42 held-out questions), and the critics' scores did not separate right from wrong answers.
- The hash chain detects edits, deletions, insertions and reordering inside one exported log. Dropping events from the end leaves a valid shorter chain, and anyone who can rewrite the whole file can rebuild it. Store the head hash separately, or sign it.
- A wall-clock timeout stops waiting, but a model call already in flight finishes in its thread; its reply is discarded.
- If a call cap falls inside a parallel critic round, which critic is refused depends on thread timing.
- When a budget or error stops the council mid-run, the evidence has the configuration, the screens, the usage and the decision, but not the partial council rounds.
- Not built: a learned classifier, signed logs, an override process for `deny`, per-client retention and deletion, persistent storage of runs, and a concrete external checker for code or arithmetic answers (the `verifier` hook exists).
