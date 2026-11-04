"""Regression tests for the security review of the MCP server (PR #2)."""

import asyncio
import json
import os
import sys
import textwrap
import time

import httpx
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from mcp_server import server as server_mod
from mcp_server.auth import GLOBAL_FAILURE_LIMIT, OAuthSettings
from mcp_server.runs import PytestRunner, child_env, parse_junit
from mcp_server.server import Settings, check_transport_security, create_server

SECRET_VALUE = "sk-test-do-not-leak-0123456789"


def make_server(root, **kwargs):
    return create_server(Settings(repo_root=root, python=sys.executable, **kwargs))


async def call(session, name, **args):
    result = await session.call_tool(name, args)
    text = result.content[0].text if result.content else ""
    if result.isError:
        return {"error": text}
    return json.loads(text)


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("# Sample\n")
    (root / "tests").mkdir()
    (root / "tests" / "test_ok.py").write_text("def test_ok():\n    assert True\n")
    return root


# -- file sandbox -------------------------------------------------------------

@pytest.mark.skipif(os.name != "posix", reason="symlinks")
async def test_symlinks_cannot_escape_or_unmask_secrets(project, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("TOP SECRET OUTSIDE\n")
    (project / "escape.txt").symlink_to(outside)
    (project / ".env").write_text("API_KEY=hunter2\n")
    (project / "innocent.txt").symlink_to(project / ".env")
    (project / "key_alias").symlink_to(project / "README.md")
    (project / "id_ed25519").write_text("PRIVATE KEY\n")
    (project / ".ssh").mkdir()
    (project / ".ssh" / "config").write_text("Host x\n")

    async with create_connected_server_and_client_session(make_server(project)) as s:
        assert "outside the repository" in (await call(s, "read_file", path="escape.txt"))["error"]
        assert "secret" in (await call(s, "read_file", path="innocent.txt"))["error"]
        assert "secret" in (await call(s, "read_file", path="id_ed25519"))["error"]
        assert "credentials directory" in (await call(s, "read_file", path=".ssh/config"))["error"]
        # a harmless alias to an allowed file is still fine
        assert (await call(s, "read_file", path="key_alias"))["content"] == "# Sample"

        listed = await call(s, "list_files")
        assert "escape.txt" not in listed["files"]
        assert "innocent.txt" not in listed["files"]
        assert "id_ed25519" not in listed["files"]
        assert not any(f.startswith(".ssh") for f in listed["files"])
        assert listed["scan"]["skipped_count"] == 2

        found = await call(s, "search_code", query="SECRET")
        assert found["matches"] == []
        found = await call(s, "search_code", query="hunter2")
        assert found["matches"] == []


async def test_read_file_streams_ranges_with_a_byte_cap(project, monkeypatch):
    big = project / "big.txt"
    with big.open("w") as fh:
        for i in range(1, 50_001):
            fh.write(f"line {i}\n")
    (project / "oneline.txt").write_text("x" * 600_000)
    monkeypatch.setattr(server_mod, "MAX_READ_BYTES", 1024)

    async with create_connected_server_and_client_session(make_server(project)) as s:
        part = await call(s, "read_file", path="big.txt", start_line=10, end_line=12)
        assert part["content"] == "line 10\nline 11\nline 12"
        assert part["total_lines"] is None  # stopped early, never read the rest
        assert part["truncated"] is False

        wide = await call(s, "read_file", path="big.txt", start_line=1, end_line=40_000)
        assert wide["truncated"] is True
        assert len(wide["content"].encode()) <= 1024

        single = await call(s, "read_file", path="oneline.txt", start_line=1, end_line=1)
        assert single["truncated"] is True
        assert len(single["content"]) <= 1024

        assert "end_line" in (await call(s, "read_file", path="big.txt",
                                         start_line=5, end_line=2))["error"]


async def test_search_reports_skipped_files_and_bounds_regex(project, monkeypatch):
    (project / "huge.txt").write_text("needle\n" + "x" * (1024 * 1024 + 10))
    (project / "blob.bin").write_bytes(b"\0needle")
    (project / "evil.txt").write_text("a" * 40 + "b\n")
    monkeypatch.setattr(server_mod, "SEARCH_TIME_BUDGET_SECONDS", 0.5)

    async with create_connected_server_and_client_session(make_server(project)) as s:
        plain = await call(s, "search_code", query="needle")
        assert "huge.txt" in plain["skipped_large_files"]
        assert "blob.bin" in plain["skipped_binary_files"]

        started = time.monotonic()
        slow = await call(s, "search_code", query=r"(a|aa)+$", regex=True, path="evil.txt")
        assert time.monotonic() - started < 10
        assert slow["timed_out"] is True

        assert "max_results" in (await call(s, "search_code", query="x", max_results=0))["error"]


# -- test runs ----------------------------------------------------------------

@pytest.mark.parametrize("timeout", [0, -1, 3601])
async def test_invalid_timeouts_are_rejected(project, timeout):
    async with create_connected_server_and_client_session(make_server(project)) as s:
        res = await call(s, "run_tests", timeout_seconds=timeout)
        assert "timeout_seconds" in res["error"]
        assert (await call(s, "list_test_runs"))["runs"] == []


async def test_keyword_cannot_inject_pytest_options(project):
    async with create_connected_server_and_client_session(make_server(project)) as s:
        res = await call(s, "run_tests", keyword="--collect-only")
        assert "-k--collect-only" in res["command"]
        assert res["status"] != "passed"  # treated as a (bad) expression, not an option
        assert "control characters" in (await call(s, "run_tests", keyword="a\nb"))["error"]


async def test_tests_do_not_see_server_secrets(project, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_VALUE)
    monkeypatch.setenv("RFAI_MCP_OAUTH_PASSWORD", "operator-password-xyz")
    (project / "tests" / "test_env.py").write_text(textwrap.dedent(f"""
        import os

        def test_env_is_scrubbed():
            print("leak:{SECRET_VALUE}")
            assert "ANTHROPIC_API_KEY" not in os.environ
            assert "RFAI_MCP_OAUTH_PASSWORD" not in os.environ
            assert "PATH" in os.environ
    """))
    async with create_connected_server_and_client_session(make_server(project)) as s:
        run = await call(s, "run_tests", target="tests/test_env.py", keyword="scrubbed",
                         include_output=True)
    assert run["status"] == "passed", run
    assert SECRET_VALUE not in run["output"]
    assert "[redacted]" in run["output"]
    assert "ANTHROPIC_API_KEY" not in child_env()


async def test_parametrized_ids_with_spaces_are_listed(project):
    (project / "tests" / "test_param.py").write_text(textwrap.dedent("""
        import pytest

        @pytest.mark.parametrize("x", [1], ids=["has space"])
        def test_p(x):
            assert x
    """))
    async with create_connected_server_and_client_session(make_server(project)) as s:
        listed = await call(s, "list_tests")
    assert "tests/test_param.py::test_p[has space]" in listed["tests"]
    assert "tests/test_ok.py::test_ok" in listed["tests"]
    assert listed["count"] == 2


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # a zombie still answers kill(0); treat it as dead
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().split()[2] != "Z"
    except FileNotFoundError:
        return False


def _write_spawning_test(project, pidfile):
    (project / "tests" / "test_spawn.py").write_text(textwrap.dedent(f"""
        import subprocess, sys, time

        def test_spawn():
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
            open({str(pidfile)!r}, "w").write(str(child.pid))
            time.sleep(120)
    """))


async def _wait_for_pid(pidfile):
    for _ in range(200):
        if pidfile.exists() and pidfile.read_text():
            return int(pidfile.read_text())
        await asyncio.sleep(0.05)
    raise AssertionError("child never started")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="uses /proc")
async def test_timeout_kills_the_whole_process_group(project, tmp_path):
    pidfile = tmp_path / "child.pid"
    _write_spawning_test(project, pidfile)
    runner = PytestRunner(project, python=sys.executable)
    record = await runner.run(target="tests/test_spawn.py", timeout_seconds=3)
    assert record.status == "timeout"
    pid = int(pidfile.read_text())
    for _ in range(40):
        if not _alive(pid):
            break
        await asyncio.sleep(0.05)
    assert not _alive(pid), "grandchild survived the timeout"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="uses /proc")
async def test_shutdown_cancels_running_tests(project, tmp_path):
    pidfile = tmp_path / "child.pid"
    _write_spawning_test(project, pidfile)
    runner = PytestRunner(project, python=sys.executable)
    record = runner.start(target="tests/test_spawn.py", timeout_seconds=120)
    pid = await _wait_for_pid(pidfile)
    await runner.shutdown()
    assert record.status == "cancelled"
    for _ in range(40):
        if not _alive(pid):
            break
        await asyncio.sleep(0.05)
    assert not _alive(pid), "grandchild survived shutdown"


def test_junit_parser_refuses_entities(tmp_path):
    report = tmp_path / "junit.xml"
    report.write_text(
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        '<testsuite><testcase classname="a" name="b"><failure message="&x;"/></testcase>'
        "</testsuite>"
    )
    summary, failures = parse_junit(report)
    assert summary == {"report_unreadable": 1}
    assert failures == []


# -- council introspection ----------------------------------------------------

async def test_describe_council_imports_runtime_out_of_process(project, tmp_path, monkeypatch):
    marker = tmp_path / "import.json"
    (project / "src").mkdir()
    (project / "src" / "rfai_prime_runtime.py").write_text(textwrap.dedent(f"""
        import json, os
        from typing import Literal
        from pydantic import BaseModel

        json.dump({{"pid": os.getpid(), "key": os.environ.get("ANTHROPIC_API_KEY")}},
                  open({str(marker)!r}, "w"))

        DEFAULT_ARCHITECT_MODEL = DEFAULT_CRITIC_MODEL = DEFAULT_INTEGRATOR_MODEL = "m"
        CRITIC_PERSPECTIVES = ["correctness"]

        class ArchitectPlan(BaseModel):
            summary: str

        class RFAIPrimeCouncil:
            def __init__(self, protocol: Literal["plan", "execute"] = "plan", max_revisions: int = 2):
                pass
    """))
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET_VALUE)
    async with create_connected_server_and_client_session(make_server(project)) as s:
        info = await call(s, "describe_council")
    assert info["critic_perspectives"] == ["correctness"]
    assert info["protocols"] == ["plan", "execute"]
    assert info["default_max_revisions"] == 2
    seen = json.loads(marker.read_text())
    assert seen["pid"] != os.getpid()
    assert seen["key"] is None


async def test_tool_annotations_reflect_code_execution(project):
    async with create_connected_server_and_client_session(make_server(project)) as s:
        tools = {t.name: t.annotations for t in (await s.list_tools()).tools}
    for name in ("list_tests", "run_tests", "describe_council", "invoke_council"):
        assert tools[name].readOnlyHint is False, name
    assert tools["invoke_council"].openWorldHint is True
    for name in ("read_file", "list_files", "search_code", "project_overview"):
        assert tools[name].readOnlyHint is True, name


# -- transport and OAuth hardening -------------------------------------------

def test_public_bind_without_oauth_is_refused(project):
    exposed = Settings(repo_root=project, host="0.0.0.0")
    assert "refusing to serve without authentication" in check_transport_security(
        "streamable-http", exposed)
    assert check_transport_security("streamable-http", Settings(repo_root=project)) is None
    assert check_transport_security("stdio", exposed) is None


def test_public_url_must_be_https(monkeypatch):
    monkeypatch.setenv("RFAI_MCP_OAUTH_PASSWORD", "a-long-enough-password")
    with pytest.raises(ValueError, match="https"):
        OAuthSettings.from_env("http://rfai.example.com")
    assert OAuthSettings.from_env("http://localhost:8000").issuer_url == "http://localhost:8000"
    assert OAuthSettings.from_env("https://rfai.example.com/").resource_url == (
        "https://rfai.example.com/mcp")


async def test_global_login_brake_survives_fresh_transactions(project):
    url = "http://localhost:8123"
    password = "correct-horse-battery"
    app = make_server(project, oauth=OAuthSettings(public_url=url, password=password)
                      ).streamable_http_app()
    redirect = "http://localhost:3030/callback"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=url) as http:
        reg = await http.post("/register", json={
            "redirect_uris": [redirect], "client_name": "t",
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "client_secret_post",
        })
        client_id = reg.json()["client_id"]

        async def fresh_txn():
            resp = await http.get("/authorize", params={
                "response_type": "code", "client_id": client_id, "redirect_uri": redirect,
                "code_challenge": "x" * 43, "code_challenge_method": "S256", "state": "s",
            })
            assert resp.status_code == 302, resp.text
            return resp.headers["location"].split("txn=")[1]

        statuses = []
        for _ in range(GLOBAL_FAILURE_LIMIT):
            txn = await fresh_txn()
            statuses.append((await http.post("/oauth/login",
                                             data={"txn": txn, "password": "wrong"})).status_code)
        assert set(statuses) == {401}
        txn = await fresh_txn()
        locked = await http.post("/oauth/login", data={"txn": txn, "password": password})
        assert locked.status_code == 429  # even the right password waits out the window
