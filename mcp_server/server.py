"""MCP server that lets an assistant (e.g. Maya) query RFAI-PRIME and run its tests."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import fnmatch
import importlib.util
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, AsyncIterator, Iterator, Literal, Optional
from urllib.parse import urlparse

import regex as safe_regex
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from mcp_server.auth import LOGIN_PATH, SCOPE, OAuthSettings, RFAIOAuthProvider
from mcp_server.introspect import IntrospectionError, describe_runtime
from mcp_server.runs import MAX_TIMEOUT_SECONDS, PytestRunner, RunError, child_env

DEFAULT_REPO_ROOT = Path(__file__).resolve().parent.parent
RUNTIME_RELATIVE_PATH = Path("src") / "rfai_prime_runtime.py"

EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "env", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "node_modules", ".idea", ".vscode",
}
# Directories that typically hold credentials; never listed, read or searched.
SECRET_DIRS = {".ssh", ".aws", ".gnupg", ".kube", ".azure", ".docker", ".secrets", "secrets"}
SECRET_FILE_PATTERNS = (
    ".env", ".env.*", "*.env", ".envrc",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.kdbx", "*.asc", "*.gpg",
    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*",
    ".netrc", ".pgpass", ".pypirc", ".npmrc", ".git-credentials", ".htpasswd",
    "credentials", "credentials.*", "*credentials*.json", "service-account*.json",
    "*.secret", "*.secrets", "secrets.*", "*oauth*state*.json",
)
MAX_READ_BYTES = 256 * 1024
MAX_SEARCH_FILE_BYTES = 1024 * 1024
MAX_RESULTS_CEILING = 2000
MAX_QUERY_CHARS = 500
SEARCH_TIME_BUDGET_SECONDS = 10.0
MAX_REPORTED_PATHS = 50
MAX_TASK_CHARS = 20_000

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}

READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
# Collecting tests imports test modules and conftest files, i.e. executes repository code.
EXECUTES_CODE = ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                idempotentHint=False, openWorldHint=False)

INSTRUCTIONS = """\
Tools for the RFAI-PRIME council runtime repository (Architect -> 5 parallel Critics ->
Integrator, with governance gates).

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
        test_timeout = int(os.environ.get("RFAI_MCP_TEST_TIMEOUT", "600"))
        if not 1 <= test_timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError(f"RFAI_MCP_TEST_TIMEOUT must be between 1 and {MAX_TIMEOUT_SECONDS}")
        return cls(
            repo_root=Path(os.environ.get("RFAI_REPO_ROOT", DEFAULT_REPO_ROOT)).resolve(),
            test_timeout=test_timeout,
            enable_council=_env_flag("RFAI_MCP_ENABLE_COUNCIL"),
            python=os.environ.get("RFAI_MCP_PYTHON", sys.executable),
            host=host or os.environ.get("RFAI_MCP_HOST", "127.0.0.1"),
            port=port or int(os.environ.get("RFAI_MCP_PORT", "8000")),
            oauth=oauth,
        )


@dataclass
class WalkReport:
    """Paths a scan could not read or deliberately skipped, so results are never silently partial."""

    errors: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "unreadable": self.errors[:MAX_REPORTED_PATHS],
            "unreadable_count": len(self.errors),
            "skipped": self.skipped[:MAX_REPORTED_PATHS],
            "skipped_count": len(self.skipped),
        }


class RepoBrowser:
    """Read-only, path-sandboxed access to the repository.

    Every path is resolved (following symlinks) and must stay inside the repository and
    outside excluded/credential directories; credential-looking files are never exposed.
    """

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    @staticmethod
    def _is_secret(name: str) -> bool:
        return any(fnmatch.fnmatch(name.lower(), pat) for pat in SECRET_FILE_PATTERNS)

    def _blocked_reason(self, candidate: Path) -> Optional[str]:
        """Why a resolved path may not be exposed, or None if it may."""
        if not candidate.is_relative_to(self.root):
            return "outside the repository"
        parts = candidate.relative_to(self.root).parts
        if any(part in EXCLUDED_DIRS for part in parts):
            return "in an excluded directory"
        if any(part.lower() in SECRET_DIRS for part in parts):
            return "in a credentials directory"
        if parts and self._is_secret(parts[-1]):
            return "a potential secret file"
        return None

    def resolve(self, rel_path: str) -> Path:
        if "\0" in rel_path:
            raise ToolError("path contains a NUL byte")
        raw = self.root / rel_path
        candidate = raw.resolve()
        reason = self._blocked_reason(candidate)
        # Also check the unresolved name, so a symlink called .env pointing at README.md is refused.
        if reason is None and raw.name and raw != self.root and self._is_secret(raw.name):
            reason = "a potential secret file"
        if reason:
            raise ToolError(f"path {rel_path!r} is {reason}")
        return candidate

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def walk(self, start: Path, report: Optional[WalkReport] = None) -> Iterator[Path]:
        """Yield exposable files under *start* (sorted, symlinked dirs not followed).

        Yields the path as seen inside the repository; files whose symlink target leaves the
        repository or lands somewhere blocked are skipped and recorded in *report*.
        """
        def onerror(exc: OSError) -> None:
            if report is not None:
                report.errors.append(self._safe_rel(exc.filename))

        for dirpath, dirnames, filenames in os.walk(start, onerror=onerror):
            dirnames[:] = sorted(
                d for d in dirnames if d not in EXCLUDED_DIRS and d.lower() not in SECRET_DIRS
            )
            for name in sorted(filenames):
                if self._is_secret(name):
                    continue
                path = Path(dirpath) / name
                try:
                    real = path.resolve()
                except OSError:
                    if report is not None:
                        report.errors.append(self._safe_rel(path))
                    continue
                if self._blocked_reason(real) is not None:
                    if report is not None:
                        report.skipped.append(f"{self._safe_rel(path)} (symlink to a blocked path)")
                    continue
                yield path

    def _safe_rel(self, path: Any) -> str:
        try:
            return Path(path).relative_to(self.root).as_posix()
        except (TypeError, ValueError):
            return str(path)

    def git(self, *args: str) -> Optional[str]:
        try:
            out = subprocess.run(
                ["git", *args], cwd=self.root, capture_output=True, text=True, timeout=10,
                stdin=subprocess.DEVNULL, env=child_env(),
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return out.stdout.strip() if out.returncode == 0 else None


def _read_head(path: Path, size: int = 8192) -> bytes:
    with path.open("rb") as fh:
        return fh.read(size)


def read_line_range(path: Path, start: int, end: Optional[int],
                    max_bytes: Optional[int] = None) -> dict[str, Any]:
    """Stream lines start..end (1-based, inclusive) without loading the whole file.

    At most *max_bytes* of content is returned; very long lines are read in bounded chunks.
    ``total_lines`` is reported only when the scan reached end of file.
    """
    if max_bytes is None:
        max_bytes = MAX_READ_BYTES
    collected: list[bytes] = []
    used = 0
    truncated = False
    lineno = 0
    reached_eof = False
    last_line = start - 1
    with path.open("rb") as fh:
        partial = False  # True while inside a line longer than one chunk
        while True:
            chunk = fh.readline(max_bytes + 1)
            if not chunk:
                reached_eof = True
                break
            if not partial:
                lineno += 1
            partial = not chunk.endswith(b"\n")
            if end is not None and lineno > end:
                break
            if lineno < start:
                continue
            if truncated:
                if end is None:
                    break
                continue
            room = max_bytes - used
            if len(chunk) > room:
                collected.append(chunk[:room])
                used = max_bytes
                truncated = True
                last_line = lineno
                continue
            collected.append(chunk)
            used += len(chunk)
            last_line = lineno
    content = b"".join(collected).decode(errors="replace")
    if content.endswith("\n"):
        content = content[:-1]
    content = content.replace("\r\n", "\n")
    return {
        "start_line": start,
        "end_line": max(last_line, start - 1),
        "total_lines": lineno if reached_eof else None,
        "truncated": truncated,
        "content": content,
    }


def load_runtime_module(repo_root: Path) -> ModuleType:
    """Import the RFAI-PRIME runtime from *repo_root* without touching sys.path.

    Only used by the opt-in ``invoke_council`` tool; ``describe_council`` inspects the
    runtime in a separate process instead.
    """
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


def _bounded_results(max_results: int) -> int:
    if not 1 <= max_results <= MAX_RESULTS_CEILING:
        raise ToolError(f"max_results must be between 1 and {MAX_RESULTS_CEILING}")
    return max_results


def create_server(settings: Optional[Settings] = None) -> FastMCP:
    settings = settings or Settings.from_env()
    repo = RepoBrowser(settings.repo_root)
    runner = PytestRunner(
        settings.repo_root, python=settings.python, default_timeout=settings.test_timeout,
    )

    @contextlib.asynccontextmanager
    async def lifespan(_: FastMCP) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await runner.shutdown()  # kill any in-flight pytest process groups

    mcp = FastMCP("rfai-prime", instructions=INSTRUCTIONS, host=settings.host,
                  port=settings.port, lifespan=lifespan, **_auth_kwargs(settings))
    mcp.runner = runner  # type: ignore[attr-defined]  # exposed for tests and shutdown

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
    async def project_overview() -> dict[str, Any]:
        """Summarise the RFAI-PRIME repository: README, layout, docs, tests and git state."""
        def build() -> dict[str, Any]:
            report = WalkReport()
            files = [repo.rel(p) for p in repo.walk(repo.root, report)]
            try:
                readme_path = repo.resolve("README.md")
                readme = (read_line_range(readme_path, 1, None)["content"]
                          if readme_path.is_file() else None)
            except ToolError:
                readme = None
            log = repo.git("log", "-5", "--pretty=format:%h %ad %an: %s", "--date=short")
            top_level = []
            for p in repo.root.iterdir():
                if p.name in EXCLUDED_DIRS or p.name.lower() in SECRET_DIRS or repo._is_secret(p.name):
                    continue
                top_level.append(p.name + ("/" if p.is_dir() else ""))
            return {
                "name": repo.root.name,
                "readme": readme,
                "top_level": sorted(top_level),
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
                "scan": report.as_dict(),
            }
        return await asyncio.to_thread(build)

    @mcp.tool(annotations=READ_ONLY)
    async def list_files(path: str = ".", pattern: str = "*",
                         max_results: int = 500) -> dict[str, Any]:
        """List repository files under `path` whose relative path matches the glob `pattern`
        (e.g. "*.py", "docs/*"). Ignores .git, virtualenvs, caches and secret files."""
        max_results = _bounded_results(max_results)
        start = repo.resolve(path)
        if not start.is_dir():
            raise ToolError(f"{path!r} is not a directory")

        def scan() -> dict[str, Any]:
            report = WalkReport()
            matches = [
                repo.rel(p) for p in repo.walk(start, report)
                if fnmatch.fnmatch(repo.rel(p), pattern)
            ]
            return {
                "files": matches[:max_results],
                "total": len(matches),
                "truncated": len(matches) > max_results,
                "scan": report.as_dict(),
            }
        return await asyncio.to_thread(scan)

    @mcp.tool(annotations=READ_ONLY)
    async def read_file(
        path: str, start_line: int = 1, end_line: Optional[int] = None
    ) -> dict[str, Any]:
        """Read a text file from the repository, optionally limited to a 1-based inclusive
        line range. At most 256 KB of content is returned per call (`truncated` says so)."""
        target = repo.resolve(path)
        if not target.is_file():
            raise ToolError(f"{path!r} is not a file")
        if start_line < 1:
            raise ToolError("start_line must be 1 or greater")
        if end_line is not None and end_line < start_line:
            raise ToolError("end_line must be greater than or equal to start_line")
        if target.stat().st_size > MAX_READ_BYTES and end_line is None:
            raise ToolError(
                f"{path!r} is larger than {MAX_READ_BYTES} bytes; pass start_line/end_line"
            )

        def read() -> dict[str, Any]:
            if b"\0" in _read_head(target):
                raise ToolError(f"{path!r} looks like a binary file")
            return {"path": repo.rel(target), **read_line_range(target, start_line, end_line)}
        return await asyncio.to_thread(read)

    @mcp.tool(annotations=READ_ONLY)
    async def search_code(
        query: str,
        path: str = ".",
        file_pattern: str = "*",
        regex: bool = False,
        case_sensitive: bool = False,
        max_results: int = 100,
    ) -> dict[str, Any]:
        """Search repository text files for `query` (plain text or a regex) and return
        matching lines as {path, line, text}. Regex searches have a time limit; files over
        1 MB, binary files and unreadable paths are reported rather than silently skipped."""
        max_results = _bounded_results(max_results)
        if not query or len(query) > MAX_QUERY_CHARS:
            raise ToolError(f"query must be 1-{MAX_QUERY_CHARS} characters")
        start = repo.resolve(path)
        if regex:
            try:
                pattern = safe_regex.compile(
                    query, 0 if case_sensitive else safe_regex.IGNORECASE
                )
            except safe_regex.error as exc:
                raise ToolError(f"invalid regex: {exc}") from exc
        needle = query if case_sensitive else query.casefold()

        def scan() -> dict[str, Any]:
            deadline = time.monotonic() + SEARCH_TIME_BUDGET_SECONDS
            report = WalkReport()
            large: list[str] = []
            binary: list[str] = []
            files = [start] if start.is_file() else repo.walk(start, report)
            results: list[dict[str, Any]] = []
            truncated = timed_out = False
            for file in files:
                rel = repo.rel(file)
                if not fnmatch.fnmatch(rel, file_pattern):
                    continue
                try:
                    if file.stat().st_size > MAX_SEARCH_FILE_BYTES:
                        large.append(rel)
                        continue
                    raw = file.read_bytes()
                except OSError:
                    report.errors.append(rel)
                    continue
                if b"\0" in raw[:8192]:
                    binary.append(rel)
                    continue
                for lineno, line in enumerate(raw.decode(errors="replace").splitlines(), 1):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    if regex:
                        try:
                            hit = pattern.search(line, timeout=remaining) is not None
                        except TimeoutError:
                            timed_out = True
                            break
                    else:
                        hit = needle in (line if case_sensitive else line.casefold())
                    if hit:
                        if len(results) >= max_results:
                            truncated = True
                            break
                        results.append({"path": rel, "line": lineno, "text": line.strip()[:500]})
                if truncated or timed_out:
                    break
            return {
                "matches": results,
                "count": len(results),
                "truncated": truncated,
                "timed_out": timed_out,
                "skipped_large_files": large[:MAX_REPORTED_PATHS],
                "skipped_binary_files": binary[:MAX_REPORTED_PATHS],
                "scan": report.as_dict(),
            }
        return await asyncio.to_thread(scan)

    @mcp.tool(annotations=EXECUTES_CODE)
    async def describe_council() -> dict[str, Any]:
        """Describe the RFAI-PRIME council configuration: roles, models (defaults and
        effective env overrides), critic perspectives, protocols, governance limits and
        data-model schemas. The runtime is imported in an isolated child process."""
        try:
            info = await describe_runtime(
                settings.python, settings.repo_root, settings.repo_root / RUNTIME_RELATIVE_PATH
            )
        except IntrospectionError as exc:
            raise ToolError(str(exc)) from exc
        defaults = info["default_models"]
        return {
            "pipeline": "Architect -> parallel Critics -> Integrator (revision loop)",
            "roles": {
                "architect": "Writes the initial draft (and an ArchitectPlan when enabled).",
                "critics": "Score the draft 1-10 in parallel, one per perspective.",
                "integrator": "Merges critic feedback into a revised or final response.",
            },
            **info,
            "effective_models": {
                role: os.environ.get(f"RFAI_{role.upper()}_MODEL", model)
                for role, model in defaults.items()
            },
            "live_invocation_enabled": settings.enable_council,
        }

    # ------------------------------------------------------------------
    # Test tools
    # ------------------------------------------------------------------

    @mcp.tool(annotations=EXECUTES_CODE)
    async def list_tests(target: Optional[str] = None) -> dict[str, Any]:
        """List pytest node ids, optionally limited to a test file/directory/node id.
        Collection imports test modules, so this executes repository code."""
        try:
            tests = await runner.collect(target)
        except RunError as exc:
            raise ToolError(str(exc)) from exc
        return {"tests": tests, "count": len(tests)}

    @mcp.tool(annotations=EXECUTES_CODE)
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
            timeout_seconds: Kill the run after this many seconds (1-3600; server default
                if unset).
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
        if not 1 <= limit <= 100:
            raise ToolError("limit must be between 1 and 100")
        return {"runs": [r.to_dict() for r in runner.list(limit)]}

    # ------------------------------------------------------------------
    # Optional live council invocation
    # ------------------------------------------------------------------

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                          idempotentHint=False, openWorldHint=True))
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
        if not task.strip() or len(task) > MAX_TASK_CHARS:
            raise ToolError(f"task must be 1-{MAX_TASK_CHARS} characters")
        rt = load_runtime_module(settings.repo_root)
        ceiling = getattr(rt, "MAX_REVISIONS_CEILING", 5)
        if not 0 <= max_revisions <= ceiling:
            raise ToolError(f"max_revisions must be between 0 and {ceiling}")
        council = rt.RFAIPrimeCouncil.from_env(protocol=protocol, max_revisions=max_revisions)
        response = await council.invoke(task)
        return response.trace.model_dump()

    # ------------------------------------------------------------------
    # Resources
    # ------------------------------------------------------------------

    def _doc(rel_path: str) -> str:
        target = repo.resolve(rel_path)
        return read_line_range(target, 1, None)["content"]

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


def check_transport_security(transport: str, settings: Settings) -> Optional[str]:
    """Return an error message if this configuration would expose tools without auth."""
    if settings.oauth is not None and transport == "stdio":
        return "OAuth requires an HTTP transport (use --transport streamable-http)"
    if transport != "stdio" and settings.oauth is None and settings.host not in LOCAL_HOSTS:
        return (
            f"refusing to serve without authentication on {settings.host}: this server can run "
            "repository code. Set RFAI_MCP_OAUTH=1 (with RFAI_MCP_PUBLIC_URL and "
            "RFAI_MCP_OAUTH_PASSWORD) or bind to 127.0.0.1."
        )
    return None


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
    problem = check_transport_security(args.transport, settings)
    if problem:
        parser.error(problem)
    if settings.oauth is not None:
        print(f"OAuth enabled; add this URL as the custom app: {settings.oauth.resource_url}",
              file=sys.stderr)
    create_server(settings).run(transport=args.transport)


if __name__ == "__main__":
    main()
