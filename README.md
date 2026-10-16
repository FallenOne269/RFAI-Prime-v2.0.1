# RFAI-PRIME Council Runtime

This repository contains an implementation of the RFAI-PRIME v2.0.1 council runtime plus accompanying design and sequence-flow documentation.

## Layout

- `src/rfai_prime_runtime.py` — runtime harness (Architect + 5 critics + Integrator).
- `docs/rfai_prime_design_doc.md` — high-level design and data model.
- `docs/rfai_prime_sequence_diagram.md` — Mermaid sequence diagram for the `invoke` path.
- `mcp_server/` — MCP server so an assistant (e.g. Maya) can query the project and run tests.
- `tests/` — pytest suite (runtime tests use a mocked Anthropic client; no API key needed).

## Quickstart

### Install

```bash
pip install -r requirements.txt        # runtime + MCP server
pip install -r requirements-dev.txt    # adds pytest
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

### Tests

```bash
python -m pytest
```

## MCP server (for Maya)

`mcp_server/` exposes the repository over the [Model Context Protocol](https://modelcontextprotocol.io)
so an MCP client can explore RFAI-PRIME and trigger test runs.

| Tool | Purpose |
|------|---------|
| `project_overview` | README, layout, docs, test files, git branch/HEAD/recent commits |
| `list_files` / `read_file` / `search_code` | Browse and search the repo (sandboxed to the repo root; skips `.git`, venvs, caches, `.env`/key files) |
| `describe_council` | Roles, default + effective models, critic perspectives, protocols, early-exit score, data-model JSON schemas |
| `list_tests` | Collect pytest node ids |
| `run_tests` | Run pytest (optional `target`, `-k` `keyword`, `timeout_seconds`); `wait=false` returns a `run_id` immediately |
| `get_test_run` / `list_test_runs` | Poll a run or list recent runs with pass/fail counts, failure details and output tail |
| `invoke_council` | Run the live council (calls Anthropic; disabled unless `RFAI_MCP_ENABLE_COUNCIL=1`) |

Resources: `rfai://readme`, `rfai://docs/design`, `rfai://docs/sequence`, `rfai://runtime`.

Only one test run executes at a time; run history is kept in memory for the server's lifetime.

### Run

```bash
python -m mcp_server                                   # stdio (default)
python -m mcp_server --transport streamable-http --port 8000   # HTTP at /mcp
```

### Client configuration

Add to your MCP client config (e.g. Claude Desktop `claude_desktop_config.json`), using absolute paths:

```json
{
  "mcpServers": {
    "rfai-prime": {
      "command": "/path/to/RFAI-Prime-v2.0.1/.venv/bin/python",
      "args": ["-m", "mcp_server"],
      "env": { "PYTHONPATH": "/path/to/RFAI-Prime-v2.0.1" }
    }
  }
}
```

| Variable | Default | Purpose |
|----------|---------|---------|
| `RFAI_REPO_ROOT` | this repo | Repository the server inspects and tests |
| `RFAI_MCP_TEST_TIMEOUT` | `600` | Default per-run timeout (seconds) |
| `RFAI_MCP_PYTHON` | current interpreter | Python used to launch pytest |
| `RFAI_MCP_ENABLE_COUNCIL` | off | Set to `1` (with `ANTHROPIC_API_KEY`) to enable `invoke_council` |
| `RFAI_MCP_TRANSPORT` / `RFAI_MCP_HOST` / `RFAI_MCP_PORT` | `stdio` / `127.0.0.1` / `8000` | Transport settings |

The HTTP transport has no authentication; keep it bound to localhost or put it behind an authenticated proxy.

## Docs

- Design doc: [docs/rfai_prime_design_doc.md](docs/rfai_prime_design_doc.md)
- Sequence diagram: [docs/rfai_prime_sequence_diagram.md](docs/rfai_prime_sequence_diagram.md)
