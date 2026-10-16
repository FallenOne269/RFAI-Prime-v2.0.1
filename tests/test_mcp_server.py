import json
import sys
import textwrap
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from pydantic import AnyUrl

from mcp_server.server import Settings, create_server

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_TOOLS = {
    "project_overview", "list_files", "read_file", "search_code", "describe_council",
    "list_tests", "run_tests", "get_test_run", "list_test_runs", "invoke_council",
}


@pytest.fixture
def sample_project(tmp_path):
    """A tiny project with one passing, one failing and one slow test."""
    (tmp_path / "README.md").write_text("# Sample\n")
    (tmp_path / ".env").write_text("SECRET=1\n")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "core.py").write_text("def add(a, b):\n    return a + b  # ADD_MARKER\n")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_sample.py").write_text(textwrap.dedent("""
        def test_pass():
            assert 1 + 1 == 2

        def test_fail():
            assert 1 + 1 == 3, "math is broken"
    """))
    (tests / "test_slow.py").write_text(textwrap.dedent("""
        import time

        def test_slow():
            time.sleep(30)
    """))
    return tmp_path


def make_server(root, **kwargs):
    return create_server(Settings(repo_root=root, python=sys.executable, **kwargs))


async def call(session, name, **args):
    result = await session.call_tool(name, args)
    text = result.content[0].text if result.content else ""
    if result.isError:
        return {"error": text}
    return json.loads(text)


async def test_lists_expected_tools(sample_project):
    async with create_connected_server_and_client_session(make_server(sample_project)) as s:
        tools = {t.name for t in (await s.list_tools()).tools}
    assert tools == EXPECTED_TOOLS


async def test_file_tools_are_sandboxed(sample_project):
    async with create_connected_server_and_client_session(make_server(sample_project)) as s:
        listing = await call(s, "list_files")
        assert "pkg/core.py" in listing["files"]
        assert ".env" not in listing["files"]

        py_only = await call(s, "list_files", pattern="*.py")
        assert all(f.endswith(".py") for f in py_only["files"])

        content = await call(s, "read_file", path="pkg/core.py", start_line=2, end_line=2)
        assert content["content"].strip() == "return a + b  # ADD_MARKER"
        assert content["total_lines"] == 2

        escaped = await call(s, "read_file", path="../etc/passwd")
        assert "outside the repository" in escaped["error"]
        assert "secret" in (await call(s, "read_file", path=".env"))["error"]


async def test_search_code(sample_project):
    async with create_connected_server_and_client_session(make_server(sample_project)) as s:
        found = await call(s, "search_code", query="add_marker")
        assert found["matches"] == [
            {"path": "pkg/core.py", "line": 2, "text": "return a + b  # ADD_MARKER"}
        ]
        regex = await call(s, "search_code", query=r"def test_\w+", regex=True,
                           file_pattern="tests/*")
        assert {m["text"] for m in regex["matches"]} >= {"def test_pass():", "def test_fail():"}
        assert "SECRET" not in json.dumps(await call(s, "search_code", query="SECRET"))


async def test_run_tests_reports_failures(sample_project):
    async with create_connected_server_and_client_session(make_server(sample_project)) as s:
        listed = await call(s, "list_tests", target="tests/test_sample.py")
        assert listed["tests"] == [
            "tests/test_sample.py::test_pass", "tests/test_sample.py::test_fail",
        ]

        run = await call(s, "run_tests", target="tests/test_sample.py", include_output=True)
        assert run["status"] == "failed"
        assert run["exit_code"] == 1
        assert run["summary"] == {"total": 2, "passed": 1, "failed": 1, "errors": 0, "skipped": 0}
        assert run["failures"][0]["test"].endswith("::test_fail")
        assert "math is broken" in run["failures"][0]["message"]
        assert "test_fail" in run["output"]

        passed = await call(s, "run_tests", target="tests/test_sample.py", keyword="test_pass")
        assert passed["status"] == "passed"
        assert passed["summary"]["total"] == 1

        history = await call(s, "list_test_runs")
        assert [r["run_id"] for r in history["runs"]] == [passed["run_id"], run["run_id"]]


async def test_background_run_and_timeout(sample_project):
    async with create_connected_server_and_client_session(make_server(sample_project)) as s:
        started = await call(s, "run_tests", target="tests/test_slow.py",
                             timeout_seconds=2, wait=False)
        assert started["status"] == "running"

        busy = await call(s, "run_tests", target="tests/test_sample.py")
        assert "still in progress" in busy["error"]

        done = await call(s, "get_test_run", run_id=started["run_id"], wait=True)
        assert done["status"] == "timeout"
        assert done["finished_at"] is not None

        assert "unknown run_id" in (await call(s, "get_test_run", run_id="nope"))["error"]


@pytest.mark.parametrize("target, message", [
    ("../outside.py", "outside the repository"),
    ("--co", "not a pytest option"),
    ("tests/missing.py", "does not exist"),
])
async def test_run_tests_rejects_bad_targets(sample_project, target, message):
    async with create_connected_server_and_client_session(make_server(sample_project)) as s:
        assert message in (await call(s, "run_tests", target=target))["error"]


async def test_describe_council_and_overview_on_real_repo():
    async with create_connected_server_and_client_session(make_server(REPO_ROOT)) as s:
        council = await call(s, "describe_council")
        assert council["critic_perspectives"] == [
            "correctness", "completeness", "security", "performance", "clarity",
        ]
        assert council["protocols"] == ["plan", "execute"]
        assert council["early_exit_score"] == 8.0
        assert set(council["data_models"]) == {
            "ArchitectPlan", "CriticFeedback", "CouncilTrace", "CouncilResponse",
        }
        assert council["live_invocation_enabled"] is False

        overview = await call(s, "project_overview")
        assert "src/rfai_prime_runtime.py" in overview["python_modules"]
        assert "tests/test_runtime.py" in overview["test_files"]
        assert "RFAI-PRIME" in overview["readme"]

        design = await s.read_resource(AnyUrl("rfai://docs/design"))
        assert "Design Document" in design.contents[0].text


async def test_invoke_council_is_gated(monkeypatch):
    async with create_connected_server_and_client_session(make_server(REPO_ROOT)) as s:
        assert "disabled" in (await call(s, "invoke_council", task="x"))["error"]

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    server = make_server(REPO_ROOT, enable_council=True)
    async with create_connected_server_and_client_session(server) as s:
        assert "ANTHROPIC_API_KEY" in (await call(s, "invoke_council", task="x"))["error"]
