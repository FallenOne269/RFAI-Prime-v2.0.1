"""MCP server that lets an assistant (e.g. Maya) query RFAI-PRIME and run its tests."""

from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import inspect
import os
import re
import subprocess
import sys
import typing
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Literal, Optional
from urllib.parse import urlparse

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from mcp_server.auth import LOGIN_PATH, SCOPE, OAuthSettings, RFAIOAuthProvider
from mcp_server.runs import PytestRunner, RunError

DEFAULT_REPO_ROOT = Path(__file__).resolve().parent.parent
RUNTIME_RELATIVE_PATH = Path("src") / "rfai_prime_runtime.py"

EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "env", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "node_modules", ".idea", ".vscode",
}
SECRET_FILE_PATTERNS = (".env", ".env.*", "*.pem", "*.key", "id_rsa*")
MAX_READ_BYTES = 256 * 1024
MAX_SEARCH_FILE_BYTES = 1024 * 1024

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}

READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)

INSTRUCTIONS = """\
Tools for the RFAI-PRIME v2.0.1 council runtime repository (Architect -> 5 parallel
Critics -> Integrator).

- Start with `project_overview` or `describe_council` to understand the project.
- Use `list_files`, `read_file`, and `search_code` to inspect source and docs.
- Use `list_tests` to discover tests and `run_tests` to execute them. Long runs can be
  started with `wait=false` and polled via `get_test_run`; `list_test_runs` shows history.
- `invoke_council` runs the live council against the Anthropic API and is only available
  when the server operator has enabled it.
"""


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    repo_root: Path = DEFAULT_REPO_ROOT
    test_timeout: int = 600
    enable_council: bool = False
    python: str = sys.executable
    host: str = "127.0.0.1"
    port: int = 8000
    oauth: Optional[OAuthSettings] = None

    @classmethod
    def from_env(cls, host: Optional[str] = None, port: Optional[int] = None) -> "Settings":
        public_url = os.environ.get("RFAI_MCP_PUBLIC_URL")
        oauth = OAuthSettings.from_env(public_url) if _env_flag("RFAI_MCP_OAUTH") else None
        return cls(
            repo_root=Path(os.environ.get("RFAI_REPO_ROOT", DEFAULT_REPO_ROOT)).resolve(),
            test_timeout=int(os.environ.get("RFAI_MCP_TEST_TIMEOUT", "600")),
            enable_council=_env_flag("RFAI_MCP_ENABLE_COUNCIL"),
            python=os.environ.get("RFAI_MCP_PYTHON", sys.executable),
            host=host or os.environ.get("RFAI_MCP_HOST", "127.0.0.1"),
            port=port or int(os.environ.get("RFAI_MCP_PORT", "8000")),
            oauth=oauth,
        )


class RepoBrowser:
    """Read-only, path-sandboxed access to the repository."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def resolve(self, rel_path: str) -> Path:
        candidate = (self.root / rel_path).resolve()
        if not candidate.is_relative_to(self.root):
            raise ToolError(f"path {rel_path!r} is outside the repository")
        rel_parts = candidate.relative_to(self.root).parts
        if any(part in EXCLUDED_DIRS for part in rel_parts):
            raise ToolError(f"path {rel_path!r} is in an excluded directory")
        if candidate.is_file() and self._is_secret(candidate.name):
            raise ToolError(f"refusing to expose potential secret file {rel_path!r}")
        return candidate

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    @staticmethod
    def _is_secret(name: str) -> bool:
        return any(fnmatch.fnmatch(name, pat) for pat in SECRET_FILE_PATTERNS)

    def walk(self, start: Path):
        for dirpath, dirnames, filenames in os.walk(start):
            dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
            for name in sorted(filenames):
                if not self._is_secret(name):
                    yield Path(dirpath) / name

    def git(self, *args: str) -> Optional[str]:
        try:
            out = subprocess.run(
                ["git", *args], cwd=self.root, capture_output=True, text=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return out.stdout.strip() if out.returncode == 0 else None


def load_runtime_module(repo_root: Path) -> ModuleType:
    """Import the RFAI-PRIME runtime from *repo_root* without touching sys.path."""
    path = repo_root / RUNTIME_RELATIVE_PATH
    if not path.is_file():
        raise ToolError(f"runtime module not found at {RUNTIME_RELATIVE_PATH.as_posix()}")
    spec = importlib.util.spec_from_file_location("rfai_prime_runtime", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except ImportError as exc:
        raise ToolError(f"could not import runtime ({exc}); install requirements.txt") from exc
    return module


def create_server(settings: Optional[Settings] = None) -> FastMCP:
    settings = settings or Settings.from_env()
    repo = RepoBrowser(settings.repo_root)
    runner = PytestRunner(
        settings.repo_root, python=settings.python, default_timeout=settings.test_timeout,
    )
    mcp = FastMCP("rfai-prime", instructions=INSTRUCTIONS, host=settings.host,
                  port=settings.port, **_auth_kwargs(settings))

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(request: Request) -> Response:
        return JSONResponse({"status": "ok", "oauth": settings.oauth is not None})

    if settings.oauth is not None:
        provider = mcp._auth_server_provider
        assert isinstance(provider, RFAIOAuthProvider)
        mcp.custom_route(LOGIN_PATH, methods=["GET", "POST"])(provider.handle_login)

    # ------------------------------------------------------------------
    # Project query tools
    # ------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    def project_overview() -> dict[str, Any]:
        """Summarise the RFAI-PRIME repository: README, layout, docs, tests and git state."""
        files = [repo.rel(p) for p in repo.walk(repo.root)]
        readme = repo.root / "README.md"
        log = repo.git("log", "-5", "--pretty=format:%h %ad %an: %s", "--date=short")
        return {
            "name": repo.root.name,
            "readme": readme.read_text(errors="replace") if readme.is_file() else None,
            "top_level": sorted(
                p.name + ("/" if p.is_dir() else "")
                for p in repo.root.iterdir()
                if p.name not in EXCLUDED_DIRS and not repo._is_secret(p.name)
            ),
            "file_count": len(files),
            "python_modules": [f for f in files if f.endswith(".py")],
            "docs": [f for f in files if f.startswith("docs/")],
            "test_files": [
                f for f in files if re.search(r"(^|/)(test_[^/]*|[^/]*_test)\.py$", f)
            ],
            "git": {
                "branch": repo.git("rev-parse", "--abbrev-ref", "HEAD"),
                "head": repo.git("rev-parse", "--short", "HEAD"),
                "recent_commits": log.splitlines() if log else [],
            },
        }

    @mcp.tool(annotations=READ_ONLY)
    def list_files(path: str = ".", pattern: str = "*", max_results: int = 500) -> dict[str, Any]:
        """List repository files under `path` whose relative path matches the glob `pattern`
        (e.g. "*.py", "docs/*"). Ignores .git, virtualenvs, caches and secret files."""
        start = repo.resolve(path)
        if not start.is_dir():
            raise ToolError(f"{path!r} is not a directory")
        matches = [
            repo.rel(p) for p in repo.walk(start) if fnmatch.fnmatch(repo.rel(p), pattern)
        ]
        return {
            "files": matches[:max_results],
            "total": len(matches),
            "truncated": len(matches) > max_results,
        }

    @mcp.tool(annotations=READ_ONLY)
    def read_file(
        path: str, start_line: int = 1, end_line: Optional[int] = None
    ) -> dict[str, Any]:
        """Read a text file from the repository, optionally limited to a 1-based inclusive
        line range."""
        target = repo.resolve(path)
        if not target.is_file():
            raise ToolError(f"{path!r} is not a file")
        if target.stat().st_size > MAX_READ_BYTES and end_line is None:
            raise ToolError(
                f"{path!r} is larger than {MAX_READ_BYTES} bytes; pass start_line/end_line"
            )
        raw = target.read_bytes()
        if b"\0" in raw[:8192]:
            raise ToolError(f"{path!r} looks like a binary file")
        lines = raw.decode(errors="replace").splitlines()
        start = max(start_line, 1)
        end = len(lines) if end_line is None else min(end_line, len(lines))
        return {
            "path": repo.rel(target),
            "start_line": start,
            "end_line": end,
            "total_lines": len(lines),
            "content": "\n".join(lines[start - 1:end]),
        }

    @mcp.tool(annotations=READ_ONLY)
    def search_code(
        query: str,
        path: str = ".",
        file_pattern: str = "*",
        regex: bool = False,
        case_sensitive: bool = False,
        max_results: int = 100,
    ) -> dict[str, Any]:
        """Search repository text files for `query` (plain text or a Python regex) and return
        matching lines as {path, line, text}."""
        start = repo.resolve(path)
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            pattern = re.compile(query if regex else re.escape(query), flags)
        except re.error as exc:
            raise ToolError(f"invalid regex: {exc}") from exc
        files = [start] if start.is_file() else repo.walk(start)
        results: list[dict[str, Any]] = []
        truncated = False
        for file in files:
            rel = repo.rel(file)
            if not fnmatch.fnmatch(rel, file_pattern):
                continue
            if file.stat().st_size > MAX_SEARCH_FILE_BYTES:
                continue
            raw = file.read_bytes()
            if b"\0" in raw[:8192]:
                continue
            for lineno, line in enumerate(raw.decode(errors="replace").splitlines(), 1):
                if pattern.search(line):
                    if len(results) >= max_results:
                        truncated = True
                        break
                    results.append({"path": rel, "line": lineno, "text": line.strip()[:500]})
            if truncated:
                break
        return {"matches": results, "count": len(results), "truncated": truncated}

    @mcp.tool(annotations=READ_ONLY)
    def describe_council() -> dict[str, Any]:
        """Describe the RFAI-PRIME council configuration: roles, models (defaults and
        effective env overrides), critic perspectives, protocols and data-model schemas."""
        rt = load_runtime_module(settings.repo_root)
        protocol_param = inspect.signature(rt.RFAIPrimeCouncil.__init__).parameters["protocol"]
        protocols = list(typing.get_args(protocol_param.annotation)) or ["plan", "execute"]
        defaults = {
            "architect": rt.DEFAULT_ARCHITECT_MODEL,
            "critic": rt.DEFAULT_CRITIC_MODEL,
            "integrator": rt.DEFAULT_INTEGRATOR_MODEL,
        }
        return {
            "pipeline": "Architect -> parallel Critics -> Integrator (revision loop)",
            "roles": {
                "architect": "Writes an ArchitectPlan and the initial draft.",
                "critics": "Score the draft 1-10 in parallel, one per perspective.",
                "integrator": "Merges critic feedback into a revised or final response.",
            },
            "default_models": defaults,
            "effective_models": {
                role: os.environ.get(f"RFAI_{role.upper()}_MODEL", model)
                for role, model in defaults.items()
            },
            "critic_perspectives": list(rt.CRITIC_PERSPECTIVES),
            "protocols": protocols,
            "early_exit_score": getattr(rt, "EARLY_EXIT_SCORE", None),
            "default_max_revisions": inspect.signature(
                rt.RFAIPrimeCouncil.__init__
            ).parameters["max_revisions"].default,
            "data_models": {
                name: getattr(rt, name).model_json_schema()
                for name in ("ArchitectPlan", "CriticFeedback", "CouncilTrace", "CouncilResponse")
            },
            "live_invocation_enabled": settings.enable_council,
        }

    # ------------------------------------------------------------------
    # Test tools
    # ------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def list_tests(target: Optional[str] = None) -> dict[str, Any]:
        """List pytest node ids, optionally limited to a test file/directory/node id."""
        try:
            tests = await runner.collect(target)
        except RunError as exc:
            raise ToolError(str(exc)) from exc
        return {"tests": tests, "count": len(tests)}

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                          idempotentHint=False, openWorldHint=False))
    async def run_tests(
        target: Optional[str] = None,
        keyword: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        wait: bool = True,
        include_output: bool = False,
    ) -> dict[str, Any]:
        """Trigger a pytest run.

        Args:
            target: Optional test path or node id (e.g. "tests/test_runtime.py::test_x").
            keyword: Optional pytest `-k` expression.
            timeout_seconds: Kill the run after this many seconds (server default if unset).
            wait: If false, return immediately with a run_id to poll via `get_test_run`.
            include_output: Include the tail of pytest's console output.
        """
        try:
            if wait:
                record = await runner.run(target, keyword, timeout_seconds)
            else:
                record = runner.start(target, keyword, timeout_seconds)
        except RunError as exc:
            raise ToolError(str(exc)) from exc
        return record.to_dict(include_output=include_output)

    @mcp.tool(annotations=READ_ONLY)
    async def get_test_run(
        run_id: str, wait: bool = False, include_output: bool = True
    ) -> dict[str, Any]:
        """Get the status and results of a test run. Set `wait` to block until it finishes."""
        try:
            record = await runner.wait(run_id) if wait else runner.get(run_id)
        except RunError as exc:
            raise ToolError(str(exc)) from exc
        return record.to_dict(include_output=include_output)

    @mcp.tool(annotations=READ_ONLY)
    def list_test_runs(limit: int = 20) -> dict[str, Any]:
        """List recent test runs (newest first) from this server session."""
        return {"runs": [r.to_dict() for r in runner.list(limit)]}

    # ------------------------------------------------------------------
    # Optional live council invocation
    # ------------------------------------------------------------------

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
    async def invoke_council(
        task: str,
        protocol: Literal["plan", "execute"] = "plan",
        max_revisions: int = 1,
    ) -> dict[str, Any]:
        """Run the live RFAI-PRIME council on `task` and return the full trace. Calls the
        Anthropic API (costs money); disabled unless RFAI_MCP_ENABLE_COUNCIL=1."""
        if not settings.enable_council:
            raise ToolError(
                "live council invocation is disabled; set RFAI_MCP_ENABLE_COUNCIL=1 "
                "and ANTHROPIC_API_KEY on the MCP server to enable it"
            )
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise ToolError("ANTHROPIC_API_KEY is not set on the MCP server")
        if not 0 <= max_revisions <= 5:
            raise ToolError("max_revisions must be between 0 and 5")
        rt = load_runtime_module(settings.repo_root)
        council = rt.RFAIPrimeCouncil.from_env(protocol=protocol, max_revisions=max_revisions)
        response = await council.invoke(task)
        return response.trace.model_dump()

    # ------------------------------------------------------------------
    # Resources
    # ------------------------------------------------------------------

    def _doc(rel_path: str) -> str:
        return repo.resolve(rel_path).read_text(errors="replace")

    @mcp.resource("rfai://readme", mime_type="text/markdown")
    def readme_resource() -> str:
        """Project README."""
        return _doc("README.md")

    @mcp.resource("rfai://docs/design", mime_type="text/markdown")
    def design_doc_resource() -> str:
        """RFAI-PRIME design document."""
        return _doc("docs/rfai_prime_design_doc.md")

    @mcp.resource("rfai://docs/sequence", mime_type="text/markdown")
    def sequence_doc_resource() -> str:
        """Mermaid sequence diagram of the invoke path."""
        return _doc("docs/rfai_prime_sequence_diagram.md")

    @mcp.resource("rfai://runtime", mime_type="text/x-python")
    def runtime_resource() -> str:
        """Council runtime source."""
        return _doc(RUNTIME_RELATIVE_PATH.as_posix())

    return mcp


def _auth_kwargs(settings: Settings) -> dict[str, Any]:
    """FastMCP constructor arguments that enable OAuth and allow the public hostname."""
    oauth = settings.oauth
    if oauth is None:
        return {}
    public = urlparse(oauth.issuer_url)
    local_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    return {
        "auth_server_provider": RFAIOAuthProvider(oauth),
        "auth": AuthSettings(
            issuer_url=AnyHttpUrl(oauth.issuer_url),
            resource_server_url=AnyHttpUrl(oauth.resource_url),
            required_scopes=[SCOPE],
            validate_token_resource=True,
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE],
            ),
            revocation_options=RevocationOptions(enabled=True),
        ),
        "transport_security": TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[public.netloc, *local_hosts],
            allowed_origins=[f"{public.scheme}://{public.netloc}", "http://127.0.0.1:*",
                             "http://localhost:*"],
        ),
    }


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m mcp_server", description=__doc__)
    parser.add_argument(
        "--transport", choices=["stdio", "streamable-http", "sse"],
        default=os.environ.get("RFAI_MCP_TRANSPORT", "stdio"),
    )
    parser.add_argument("--host", default=None, help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="bind port (default 8000)")
    args = parser.parse_args(argv)

    try:
        settings = Settings.from_env(host=args.host, port=args.port)
    except ValueError as exc:
        parser.error(str(exc))
    if settings.oauth is not None and args.transport == "stdio":
        parser.error("OAuth requires an HTTP transport (use --transport streamable-http)")
    if args.transport != "stdio" and settings.oauth is None and settings.host not in LOCAL_HOSTS:
        print(f"WARNING: serving without authentication on {settings.host}; set RFAI_MCP_OAUTH=1",
              file=sys.stderr)
    if settings.oauth is not None:
        print(f"OAuth enabled; add this URL as the custom app: {settings.oauth.resource_url}",
              file=sys.stderr)
    create_server(settings).run(transport=args.transport)


if __name__ == "__main__":
    main()
