"""Describe the council runtime without importing repository code into the server.

``describe_council`` has to import ``src/rfai_prime_runtime.py`` to read its constants and
pydantic schemas. Importing runs that module's top-level code, so it is done in a separate
Python process with the same isolation as test runs (no shell, scrubbed environment, its
own process group, a timeout and bounded output). The server only parses the JSON it prints.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_server.runs import run_bounded

DESCRIBE_TIMEOUT_SECONDS = 60
MARKER = "@@RFAI_DESCRIBE@@"

_SCRIPT = r'''
import importlib.util, inspect, json, sys, typing
path = sys.argv[1]
spec = importlib.util.spec_from_file_location("rfai_prime_runtime", path)
rt = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(rt)
except ImportError as exc:
    print("@@RFAI_DESCRIBE@@" + json.dumps({"error": f"could not import runtime ({exc}); install requirements.txt"}))
    sys.exit(0)
params = inspect.signature(rt.RFAIPrimeCouncil.__init__).parameters
protocols = list(typing.get_args(params["protocol"].annotation)) or ["plan", "execute"]
def default(name):
    p = params.get(name)
    return None if p is None or p.default is inspect.Parameter.empty else p.default
out = {
    "default_models": {
        "architect": rt.DEFAULT_ARCHITECT_MODEL,
        "critic": rt.DEFAULT_CRITIC_MODEL,
        "integrator": rt.DEFAULT_INTEGRATOR_MODEL,
    },
    "critic_perspectives": list(rt.CRITIC_PERSPECTIVES),
    "protocols": protocols,
    "early_exit_score": getattr(rt, "EARLY_EXIT_SCORE", None),
    "max_revisions_ceiling": getattr(rt, "MAX_REVISIONS_CEILING", None),
    "min_readable_critics": getattr(rt, "MIN_READABLE_CRITICS", None),
    "default_max_revisions": default("max_revisions"),
    "strict_gate_default": default("strict_gate"),
    "data_models": {
        name: getattr(rt, name).model_json_schema()
        for name in ("ArchitectPlan", "CriticFeedback", "CouncilTrace", "CouncilResponse")
        if hasattr(rt, name)
    },
}
print("@@RFAI_DESCRIBE@@" + json.dumps(out))
'''


class IntrospectionError(Exception):
    pass


async def describe_runtime(python: str, repo_root: Path, runtime_path: Path) -> dict[str, Any]:
    if not runtime_path.is_file():
        raise IntrospectionError("runtime module not found at src/rfai_prime_runtime.py")
    code, output, timed_out = await run_bounded(
        [python, "-I", "-c", _SCRIPT, str(runtime_path)],
        repo_root,
        timeout=DESCRIBE_TIMEOUT_SECONDS,
        limit=2 * 1024 * 1024,
    )
    if timed_out:
        raise IntrospectionError("describing the runtime timed out")
    line = next((ln for ln in reversed(output.splitlines()) if ln.startswith(MARKER)), None)
    if code != 0 or line is None:
        raise IntrospectionError(f"could not describe the runtime (exit {code}):\n{output[-2000:]}")
    data = json.loads(line[len(MARKER):])
    if "error" in data:
        raise IntrospectionError(data["error"])
    return data
