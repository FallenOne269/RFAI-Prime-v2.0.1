# RFAI-PRIME Council Runtime

This repository contains an implementation of the RFAI-PRIME v2.0.1 council runtime plus accompanying design and sequence-flow documentation.

## Layout

- `src/rfai_prime_runtime.py` — runtime harness (Architect + 5 critics + Integrator).
- `docs/rfai_prime_design_doc.md` — high-level design and data model.
- `docs/rfai_prime_sequence_diagram.md` — Mermaid sequence diagram for the `invoke` path.
- `src/governance/` — v2.1 candidate governance layer: policy screen (allow / review / deny), budgets, hash-chained evidence log, human review. See `docs/GOVERNANCE.md`.
- `policies/`, `scenarios/` — default Discovery policy and the 15-scenario acceptance suite.
- `mcp_server/` — Python MCP server so an assistant (e.g. Maya) can query this repository and run its tests.
- `mcp/` — separate TypeScript MCP server for the governed council (OAuth, Koyeb guide in `mcp/DEPLOY_KOYEB.md`).
- `tests/` — pytest suite with scripted model replies; no API key needed (`python -m pytest -q tests`).

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

### Safety model

The test tools (`list_tests`, `run_tests`) and `describe_council` execute repository code, so they are
annotated as not read-only. Every child process (pytest, collection, runtime introspection) is started
without a shell, with `stdin` from `/dev/null`, in its own process group (a timeout, cancellation or
server shutdown kills pytest and anything it spawned), and with a scrubbed environment: variables whose
names look like credentials (`*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `RFAI_MCP_*`, ...) are removed,
and their values are redacted from returned output. `describe_council` imports the runtime in a child
process, never in the server. `-k` expressions are passed attached (`-k<expr>`) so they cannot become
pytest options; `timeout_seconds` must be 1-3600. JUnit reports are parsed with `defusedxml`.

File tools resolve symlinks and refuse anything outside the repository, in `.git`/venv/cache or
credential directories (`.ssh`, `.aws`, ...), or named like a secret (`.env*`, `*.pem`, `*.key`,
`id_ed25519*`, `.netrc`, `credentials*`, ...). `read_file` streams ranges with a 256 KB cap, regex search
has a time limit, and scans report unreadable, oversized and binary files instead of skipping them silently.

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

Without OAuth the HTTP transport has no authentication, so the server refuses to bind anything other than
localhost unless OAuth is enabled.

### Remote access with OAuth (Sesame custom app)

Set `RFAI_MCP_OAUTH=1` to protect the HTTP transport with OAuth 2.1, following the
[MCP authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization).
The server acts as its own authorization server. It publishes protected-resource and
authorization-server metadata, supports dynamic client registration, uses authorization code + PKCE (S256),
rotates refresh tokens, and supports revocation. When a client is authorized, the operator approves it on a
consent page protected by `RFAI_MCP_OAUTH_PASSWORD`. Five wrong passwords lock one sign-in attempt, and 20
wrong passwords across all attempts pause sign-in for 15 minutes. `RFAI_MCP_PUBLIC_URL` must be `https://`
(plain http is accepted only for localhost).

```bash
export RFAI_MCP_OAUTH=1
export RFAI_MCP_PUBLIC_URL=https://rfai.example.com          # public HTTPS origin (behind TLS proxy)
export RFAI_MCP_OAUTH_PASSWORD='a-long-random-passphrase'    # >= 12 chars, keep secret
export RFAI_MCP_OAUTH_STATE_FILE=/var/lib/rfai-mcp/oauth.json  # optional: survive restarts
python -m mcp_server --transport streamable-http --host 127.0.0.1 --port 8000
```

In Sesame, add a custom app with the URL `https://rfai.example.com/mcp` and pick OAuth. Sesame discovers
the endpoints, registers itself, and opens the consent page. Enter the password there and click **Approve**.
If the client needs a pre-registered client ID/secret instead of dynamic registration, set
`RFAI_MCP_OAUTH_CLIENT_ID`, `RFAI_MCP_OAUTH_CLIENT_SECRET` and `RFAI_MCP_OAUTH_REDIRECT_URIS`
(comma-separated, use the callback URL Sesame shows) and enter the same values in Sesame.

| Variable | Default | Purpose |
|----------|---------|---------|
| `RFAI_MCP_OAUTH` | off | Enable OAuth on HTTP transports (refused with stdio) |
| `RFAI_MCP_PUBLIC_URL` | required | Externally reachable origin; issuer and resource URL (`<url>/mcp`) |
| `RFAI_MCP_OAUTH_PASSWORD` | required | Operator password for the consent page |
| `RFAI_MCP_OAUTH_STATE_FILE` | in memory | JSON file (mode 0600) persisting clients and tokens. Without it, every restart signs clients out |
| `RFAI_MCP_OAUTH_CLIENT_ID` / `_CLIENT_SECRET` / `_REDIRECT_URIS` | unset | Optional pre-registered client |
| `RFAI_MCP_ACCESS_TOKEN_TTL` / `RFAI_MCP_REFRESH_TOKEN_TTL` | `3600` / `2592000` | Token lifetimes (seconds) |

Requests whose `Host` is neither the public host nor localhost are rejected (DNS-rebinding protection),
so your proxy must forward the original `Host` header or connect to `127.0.0.1`. Terminate TLS in front
of the server. Never expose plain HTTP publicly. `GET /healthz` is an unauthenticated liveness probe.

## Docs

- Design doc: [docs/rfai_prime_design_doc.md](docs/rfai_prime_design_doc.md)
- Sequence diagram: [docs/rfai_prime_sequence_diagram.md](docs/rfai_prime_sequence_diagram.md)
