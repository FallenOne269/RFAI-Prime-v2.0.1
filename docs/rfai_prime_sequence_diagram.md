[← Design Doc](rfai_prime_design_doc.md) · [Runtime →](../src/rfai_prime_runtime.py)

---

# RFAI-PRIME v2.0.1 — Sequence Diagram

## `invoke` Path

```mermaid
sequenceDiagram
    actor User
    participant Council as RFAIPrimeCouncil
    participant Arch as Architect<br/>(claude-opus-4-6)
    participant C1 as Critic: Correctness<br/>(claude-sonnet-4-6)
    participant C2 as Critic: Completeness<br/>(claude-sonnet-4-6)
    participant C3 as Critic: Security<br/>(claude-sonnet-4-6)
    participant C4 as Critic: Performance<br/>(claude-sonnet-4-6)
    participant C5 as Critic: Clarity<br/>(claude-sonnet-4-6)
    participant Integ as Integrator<br/>(claude-opus-4-6)

    User->>Council: invoke(task)
    Council->>Arch: _architect(task, protocol)
    Arch-->>Council: ArchitectPlan + draft

    loop Revision loop (up to max_revisions)
        par Parallel critic calls
            Council->>C1: _critic(task, draft, "correctness")
            Council->>C2: _critic(task, draft, "completeness")
            Council->>C3: _critic(task, draft, "security")
            Council->>C4: _critic(task, draft, "performance")
            Council->>C5: _critic(task, draft, "clarity")
        end
        C1-->>Council: CriticFeedback
        C2-->>Council: CriticFeedback
        C3-->>Council: CriticFeedback
        C4-->>Council: CriticFeedback
        C5-->>Council: CriticFeedback

        Council->>Council: avg_score = mean(scores)

        alt avg_score >= 8.0 or revisions == max_revisions
            Council->>Council: break
        else
            Council->>Integ: _integrator(task, draft, feedbacks)
            Integ-->>Council: revised draft
        end
    end

    Council->>Integ: _integrator(task, draft, feedbacks)
    Integ-->>Council: final_text
    Council-->>User: CouncilResponse(final_text, trace)
```

## Notes

- Critic calls run fully in parallel via `asyncio.gather`.
- The Integrator is called once per revision iteration (to produce a revised draft) and once at the end (final synthesis).
- Early exit fires when the average critic score reaches **8.0** or the revision budget is exhausted — whichever comes first.
- All Anthropic API calls are dispatched with `asyncio.to_thread`; the event loop is never blocked.
