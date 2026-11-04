"""Pytest run management for the RFAI-PRIME MCP server.

Every child process started here:

- is launched without a shell, from an argument list;
- gets ``stdin`` from ``/dev/null`` (so it can never read the MCP stdio channel);
- gets a scrubbed environment with credentials removed (see :func:`child_env`);
- runs in its own process group, so a timeout, cancellation or server shutdown kills
  pytest *and* anything it spawned;
- has its output kept as a bounded in-memory tail, with known secret values redacted.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import signal
import sys
import tempfile
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import ParseError

OUTPUT_TAIL_CHARS = 12_000
OUTPUT_TAIL_BYTES = 64 * 1024
MAX_JUNIT_BYTES = 20 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 3600
MAX_KEYWORD_CHARS = 200
MAX_TARGET_CHARS = 500
REDACTED = "[redacted]"

PYTEST_EXIT_STATUS = {
    0: "passed",
    1: "failed",
    2: "interrupted",
    3: "internal_error",
    4: "usage_error",
    5: "no_tests_collected",
}

# Environment variables whose names look like credentials are never passed to test code.
_SENSITIVE_ENV = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIAL|COOKIE|SESSION|AUTH|PRIVATE|DSN)",
    re.IGNORECASE,
)
_ALWAYS_DROP_PREFIXES = ("RFAI_MCP_", "AWS_", "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_")
_MIN_REDACT_LEN = 6


class RunError(Exception):
    """Raised when a test run cannot be started or found."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _is_sensitive_env(name: str) -> bool:
    return name.startswith(_ALWAYS_DROP_PREFIXES) or bool(_SENSITIVE_ENV.search(name))


def child_env(extra: Optional[dict[str, str]] = None) -> dict[str, str]:
    """The server environment minus anything that looks like a credential."""
    env = {k: v for k, v in os.environ.items() if not _is_sensitive_env(k)}
    env["PYTHONUNBUFFERED"] = "1"
    env.update(extra or {})
    return env


def secret_values() -> list[str]:
    """Values of the server's sensitive environment variables, longest first."""
    values = {
        v for k, v in os.environ.items()
        if _is_sensitive_env(k) and len(v) >= _MIN_REDACT_LEN
    }
    return sorted(values, key=len, reverse=True)


def redact(text: str, secrets: Optional[list[str]] = None) -> str:
    for value in secrets if secrets is not None else secret_values():
        text = text.replace(value, REDACTED)
    return text


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    """Kill *proc* and every process in its group (POSIX); fall back to proc.kill()."""
    if proc.returncode is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:  # pragma: no cover - Windows
            proc.kill()
    except ProcessLookupError:
        pass


async def _spawn(cmd: list[str], cwd: Path) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=child_env(),
        start_new_session=(os.name == "posix"),
    )


async def _read_tail(stream: asyncio.StreamReader, limit: int) -> bytes:
    """Drain *stream*, keeping only the last *limit* bytes in memory."""
    tail = bytearray()
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return bytes(tail)
        tail += chunk
        if len(tail) > limit:
            del tail[:-limit]


async def run_bounded(cmd: list[str], cwd: Path, timeout: float,
                      limit: int = OUTPUT_TAIL_BYTES) -> tuple[Optional[int], str, bool]:
    """Run *cmd* to completion or timeout. Returns (exit code, output tail, timed_out).

    The process group is killed on timeout and on cancellation.
    """
    proc = await _spawn(cmd, cwd)
    assert proc.stdout is not None
    reader = asyncio.ensure_future(_read_tail(proc.stdout, limit))
    timed_out = False
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        timed_out = True
        _kill_group(proc)
        await proc.wait()
    except BaseException:
        _kill_group(proc)
        await proc.wait()
        reader.cancel()
        raise
    try:
        out = await asyncio.wait_for(reader, timeout=5)
    except asyncio.TimeoutError:  # a grandchild still holds the pipe open
        reader.cancel()
        out = b""
    if os.name == "posix":  # leftovers in the group (e.g. a daemonised grandchild)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    return proc.returncode, redact(out.decode(errors="replace")), timed_out


@dataclass
class RunRecord:
    run_id: str
    command: list[str]
    target: Optional[str]
    keyword: Optional[str]
    timeout_seconds: int
    status: str = "running"
    started_at: str = field(default_factory=_now)
    finished_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    exit_code: Optional[int] = None
    summary: dict[str, int] = field(default_factory=dict)
    failures: list[dict[str, str]] = field(default_factory=list)
    output: str = ""

    def to_dict(self, include_output: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "run_id": self.run_id,
            "status": self.status,
            "command": " ".join(self.command),
            "target": self.target,
            "keyword": self.keyword,
            "timeout_seconds": self.timeout_seconds,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "summary": self.summary,
            "failures": self.failures,
        }
        if include_output:
            data["output"] = self.output[-OUTPUT_TAIL_CHARS:]
        return data


def parse_junit(path: Path) -> tuple[dict[str, int], list[dict[str, str]]]:
    """Return (summary counts, failure details) from a pytest JUnit XML report.

    Parsed with defusedxml (no DTDs, entities or external references) and size-capped.
    """
    if not path.is_file():
        return {}, []
    if path.stat().st_size > MAX_JUNIT_BYTES:
        return {"report_too_large": 1}, []
    try:
        root = SafeET.parse(path, forbid_dtd=True).getroot()
    except (ParseError, DefusedXmlException):
        return {"report_unreadable": 1}, []
    secrets = secret_values()
    counts = {"total": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    failures: list[dict[str, str]] = []
    for case in root.iter("testcase"):
        counts["total"] += 1
        test_id = f"{case.get('classname', '')}::{case.get('name', '')}"
        outcome = "passed"
        for child in case:
            if child.tag in ("failure", "error"):
                outcome = "failed" if child.tag == "failure" else "errors"
                failures.append({
                    "test": test_id,
                    "kind": child.tag,
                    "message": redact((child.get("message") or "").strip()[:2000], secrets),
                    "details": redact((child.text or "").strip()[-4000:], secrets),
                })
                break
            if child.tag == "skipped":
                outcome = "skipped"
        counts[outcome] += 1
    return counts, failures


class PytestRunner:
    """Launches pytest in a subprocess and keeps an in-memory run history."""

    def __init__(
        self,
        repo_root: Path,
        python: str = sys.executable,
        default_timeout: int = 600,
        max_history: int = 50,
    ) -> None:
        self.repo_root = repo_root.resolve()
        self.python = python
        self.default_timeout = default_timeout
        self.max_history = max_history
        self._runs: OrderedDict[str, RunRecord] = OrderedDict()
        self._tasks: dict[str, asyncio.Task[None]] = {}

    def validate_target(self, target: Optional[str]) -> Optional[str]:
        if not target:
            return None
        if len(target) > MAX_TARGET_CHARS or any(c in target for c in "\0\r\n"):
            raise RunError("target is too long or contains control characters")
        if target.startswith("-"):
            raise RunError("target must be a test path or node id, not a pytest option")
        file_part = target.split("::", 1)[0]
        resolved = (self.repo_root / file_part).resolve()
        if not resolved.is_relative_to(self.repo_root):
            raise RunError(f"target {target!r} is outside the repository")
        if not resolved.exists():
            raise RunError(f"target {file_part!r} does not exist")
        return target

    @staticmethod
    def validate_keyword(keyword: Optional[str]) -> Optional[str]:
        if not keyword:
            return None
        if len(keyword) > MAX_KEYWORD_CHARS or any(c in keyword for c in "\0\r\n"):
            raise RunError("keyword is too long or contains control characters")
        return keyword

    def validate_timeout(self, timeout_seconds: Optional[int]) -> int:
        if timeout_seconds is None:
            return self.default_timeout
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
            raise RunError("timeout_seconds must be a whole number of seconds")
        if not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise RunError(f"timeout_seconds must be between 1 and {MAX_TIMEOUT_SECONDS}")
        return timeout_seconds

    def _base_command(self) -> list[str]:
        return [self.python, "-m", "pytest", "-p", "no:cacheprovider"]

    def _is_node_id(self, line: str) -> bool:
        if "::" not in line:
            return False
        file_part = line.split("::", 1)[0]
        if not file_part or file_part != file_part.strip():
            return False
        candidate = (self.repo_root / file_part).resolve()
        return candidate.is_relative_to(self.repo_root) and candidate.is_file()

    async def collect(self, target: Optional[str] = None) -> list[str]:
        """Return the node ids pytest would run for *target*."""
        target = self.validate_target(target)
        cmd = self._base_command() + ["--collect-only", "-q"]
        if target:
            cmd.append(target)
        code, text, timed_out = await run_bounded(
            cmd, self.repo_root, timeout=self.default_timeout, limit=4 * 1024 * 1024
        )
        if timed_out:
            raise RunError("test collection timed out")
        if code not in (0, 5):
            raise RunError(f"test collection failed (exit {code}):\n{text[-4000:]}")
        # Keep parametrised ids that contain spaces; drop summary/warning lines.
        return [line for line in text.splitlines() if self._is_node_id(line)]

    def start(
        self,
        target: Optional[str] = None,
        keyword: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
    ) -> RunRecord:
        """Start a pytest run in the background and return its record."""
        running = [r.run_id for r in self._runs.values() if r.status == "running"]
        if running:
            raise RunError(f"test run {running[0]} is still in progress")
        target = self.validate_target(target)
        keyword = self.validate_keyword(keyword)
        timeout = self.validate_timeout(timeout_seconds)

        workdir = Path(tempfile.mkdtemp(prefix="rfai-mcp-run-"))
        junit = workdir / "junit.xml"
        cmd = self._base_command() + ["-rA", f"--junitxml={junit}"]
        if keyword:
            # Attached form: the value can never be parsed as another pytest option.
            cmd.append(f"-k{keyword}")
        if target:
            cmd.append(target)

        record = RunRecord(
            run_id=uuid.uuid4().hex[:12],
            command=cmd,
            target=target,
            keyword=keyword,
            timeout_seconds=timeout,
        )
        self._remember(record)
        self._tasks[record.run_id] = asyncio.create_task(self._execute(record, workdir, junit))
        return record

    async def run(
        self,
        target: Optional[str] = None,
        keyword: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
    ) -> RunRecord:
        """Run pytest and wait for it to finish."""
        record = self.start(target, keyword, timeout_seconds)
        await self.wait(record.run_id)
        return record

    async def wait(self, run_id: str) -> RunRecord:
        record = self.get(run_id)
        task = self._tasks.get(run_id)
        if task is not None:
            await asyncio.shield(task)
        return record

    def get(self, run_id: str) -> RunRecord:
        try:
            return self._runs[run_id]
        except KeyError:
            raise RunError(f"unknown run_id {run_id!r}") from None

    def list(self, limit: int = 20) -> list[RunRecord]:
        return list(reversed(self._runs.values()))[:max(0, limit)]

    async def shutdown(self) -> None:
        """Cancel in-flight runs; each one kills its pytest process group."""
        tasks = list(self._tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _remember(self, record: RunRecord) -> None:
        self._runs[record.run_id] = record
        while len(self._runs) > self.max_history:
            old_id, old = next(iter(self._runs.items()))
            if old.status == "running":
                break
            self._runs.pop(old_id)

    async def _execute(self, record: RunRecord, workdir: Path, junit: Path) -> None:
        start = time.monotonic()
        try:
            code, output, timed_out = await run_bounded(
                record.command, self.repo_root, timeout=record.timeout_seconds
            )
            record.exit_code = code
            record.status = "timeout" if timed_out else PYTEST_EXIT_STATUS.get(code, "error")
            record.output = output[-OUTPUT_TAIL_CHARS:]
            record.summary, record.failures = parse_junit(junit)
        except asyncio.CancelledError:
            record.status = "cancelled"
            raise
        except Exception as exc:  # noqa: BLE001 - surface any launcher failure to the client
            record.status = "error"
            record.output += f"\n[rfai-mcp] failed to run pytest: {type(exc).__name__}"
        finally:
            record.duration_seconds = round(time.monotonic() - start, 3)
            record.finished_at = _now()
            self._tasks.pop(record.run_id, None)
            shutil.rmtree(workdir, ignore_errors=True)
