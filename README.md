# RFAI-PRIME Council Runtime

This repository contains an implementation of the RFAI-PRIME v2.0.1 council runtime plus accompanying design and sequence-flow documentation.

## Layout

- `src/rfai_prime_runtime.py` — runtime harness (Architect + 5 critics + Integrator).
- `docs/rfai_prime_design_doc.md` — high-level design and data model.
- `docs/rfai_prime_sequence_diagram.md` — Mermaid sequence diagram for the `invoke` path.
- `src/governance/` — v2.1 candidate governance layer: policy screen (allow / review / deny), budgets, hash-chained evidence log, human review. See `docs/GOVERNANCE.md`.
- `policies/`, `scenarios/` — default Discovery policy and the 15-scenario acceptance suite.
- `tests/` — 87 tests with scripted model replies (`python -m pytest -q tests`).

## Quickstart

### Install

```bash
pip install anthropic pydantic
```

### Environment

```bash
export ANTHROPIC_API_KEY="your_key_here"
# optional overrides
export RFAI_ARCHITECT_MODEL="claude-opus-4-6"
export RFAI_CRITIC_MODEL="claude-sonnet-4-6"
export RFAI_INTEGRATOR_MODEL="claude-opus-4-6"
```

### Programmatic use

```python
import asyncio
from src.rfai_prime_runtime import RFAIPrimeCouncil

async def main():
    council = RFAIPrimeCouncil.from_env(protocol="execute")
    resp = await council.invoke("Design a fault-tolerant task queue.")
    print(resp.final_text)
    print(resp.trace.model_dump_json(indent=2))

asyncio.run(main())
```

### CLI

```bash
python -m src.rfai_prime_runtime invoke "Your task here"
python -m src.rfai_prime_runtime invoke \
  --protocol execute \
  --max-revisions 1 \
  --json "Ship a rate limiter."
```

## Docs

- Design doc: [docs/rfai_prime_design_doc.md](docs/rfai_prime_design_doc.md)
- Sequence diagram: [docs/rfai_prime_sequence_diagram.md](docs/rfai_prime_sequence_diagram.md)
