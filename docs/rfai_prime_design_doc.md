[← Runtime](../src/rfai_prime_runtime.py) · [Sequence Diagram →](rfai_prime_sequence_diagram.md)

---

# RFAI-PRIME v2.0.1 — Design Document

## Overview

RFAI-PRIME (**R**ecursive **F**eedback **AI** with **P**arallel **I**terative **M**ulti-**E**xpert) is a council-based runtime that routes every task through three tiers of Claude models: an **Architect**, a parallel panel of **Critics**, and an **Integrator**. Each tier adds a quality gate; the revision loop runs until the panel consensus is high enough or the revision budget is exhausted.

## Goals

- Produce higher-quality responses than a single LLM call by leveraging multi-perspective critique.
- Support two protocols: `plan` (structured reasoning) and `execute` (implementation-focused output).
- Bound latency through configurable `max_revisions` with early exit when the average critic score reaches 8.0/10.

## Architecture

### Roles

| Role | Count | Default model | Responsibility |
|------|-------|---------------|----------------|
| Architect | 1 | `claude-opus-4-6` | Decomposes the task, writes a structured `ArchitectPlan`, and produces the initial draft. |
| Critic | 5 | `claude-sonnet-4-6` | Each critic evaluates the draft from a dedicated perspective (see below). All five run in parallel. |
| Integrator | 1 | `claude-opus-4-6` | Merges critic feedback into a revised or final response. |

### Critic Perspectives

| Perspective | Focus |
|-------------|-------|
| **Correctness** | Factual accuracy and logical soundness |
| **Completeness** | Missing requirements, edge cases, or assumptions |
| **Security** | Vulnerabilities, trust boundaries, data-exposure risks |
| **Performance** | Algorithmic complexity, resource usage, scalability |
| **Clarity** | Readability, naming, structure, and documentation |

### Data Model

```
ArchitectPlan
  summary    : str
  approach   : str
  concerns   : list[str]

CriticFeedback
  perspective : str
  score       : int          # 1–10
  feedback    : str
  suggestions : list[str]

CouncilTrace
  task              : str
  protocol          : str
  architect_plan    : ArchitectPlan
  critic_feedbacks  : list[CriticFeedback]
  revisions         : int
  final_text        : str

CouncilResponse
  final_text : str
  trace      : CouncilTrace
```

## Revision Loop

```
1. Architect(task, protocol) → (ArchitectPlan, draft)
2. Critics × 5 run in parallel against draft → list[CriticFeedback]
3. avg_score = mean(f.score for f in feedbacks)
4. If avg_score ≥ 8.0 OR revisions == max_revisions → go to 6
5. Integrator(task, draft, feedbacks) → revised draft; revisions += 1; go to 2
6. Integrator(task, draft, feedbacks) → final_text
7. Return CouncilResponse(final_text, CouncilTrace)
```

Critics run concurrently via `asyncio.gather`; each Anthropic API call is dispatched with `asyncio.to_thread` so the event loop stays free.

## Configuration

All models and the API key are resolved from environment variables with hardcoded fallbacks:

| Variable | Default |
|----------|---------|
| `ANTHROPIC_API_KEY` | *(required)* |
| `RFAI_ARCHITECT_MODEL` | `claude-opus-4-6` |
| `RFAI_CRITIC_MODEL` | `claude-sonnet-4-6` |
| `RFAI_INTEGRATOR_MODEL` | `claude-opus-4-6` |

## Protocols

| Protocol | Architect prompt emphasis | Typical use |
|----------|---------------------------|-------------|
| `plan` | Structured reasoning, trade-offs, design decisions | Architecture questions, analysis |
| `execute` | Concrete implementation output | Code generation, drafting |

## Dependencies

| Package | Role |
|---------|------|
| `anthropic` | Anthropic Python SDK (messages API) |
| `pydantic` | Data model validation and JSON serialisation |
