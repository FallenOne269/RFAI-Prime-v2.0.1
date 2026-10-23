"""Run an acceptance-scenario suite through the governed council and write an evidence pack.

    python -m src.governance.discovery_demo                       # offline, scripted replies
    python -m src.governance.discovery_demo --backend local \
        --url http://127.0.0.1:8080/v1/chat/completions          # a local OpenAI-compatible model

With the scripted backend every scenario has an expected result, and the exit code is
non-zero if any check fails. With a live model the model's behaviour decides the council
signals, so only scenarios decided before any model call (blocked at input) are pass/fail;
the rest are recorded as observed.

Outputs (in --out): evidence_pack.json (every run's summary and full hash-chained events)
and acceptance_report.md.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import itertools
import json
import sys
from pathlib import Path

from .adapters import OpenAICompatClient, ScriptedClient
from .budget import ExecutionBudget
from .evidence import verify_chain
from .review import ReviewError, ReviewRecord, apply_review
from .runner import RUNTIME_VERSION, GovernedCouncil, JobContext, default_council_factory
from .safety_guard import SafetyGuard, load_policy

ROOT = Path(__file__).resolve().parents[2]


def scripted_responder(script: dict):
    def respond(role: str, prompt: str, n: int) -> str:
        if script.get("down"):
            raise ConnectionError("provider unavailable (scripted)")
        if role == "architect":
            return script["draft"]
        if role.startswith("critic:"):
            c = script.get("critic", 9)
            if c == "unreadable":
                return "Looks solid overall, maybe a 9 out of 10."
            if c == "error":
                raise TimeoutError("critic timed out (scripted)")
            return json.dumps({"perspective": role[7:], "score": c, "feedback": "scripted", "suggestions": []})
        return script.get("final", script["draft"])
    return respond


def fixed_clocks():
    tick = itertools.count()
    mono = itertools.count()
    return (lambda: f"2026-01-01T00:00:{next(tick) % 60:02d}.000+00:00"), (lambda: float(next(mono)) * 0.001)


async def run_scenario(sc: dict, policy, backend: str, url: str, fixed: bool, max_revisions: int) -> dict:
    if backend == "scripted":
        client = ScriptedClient(scripted_responder(sc["script"]))
    else:
        client = OpenAICompatClient(url=url)
    budget = ExecutionBudget(**sc.get("budget", {}))
    kw = {}
    if fixed:
        kw["clock"], kw["monotonic"] = fixed_clocks()
    gc = GovernedCouncil(client, SafetyGuard(policy), budget=budget,
                         council_factory=default_council_factory(max_revisions=max_revisions), **kw)
    ctx = JobContext(job_id=sc["id"], **sc.get("context", {}))
    res = await gc.run(sc["task"], ctx, run_id=sc["id"])
    outcomes = [res.outcome]
    review_errors = []
    for r in sc.get("reviews", []):
        try:
            apply_review(res, ReviewRecord(**r))
        except ReviewError as e:
            review_errors.append(str(e))
        outcomes.append(res.outcome)

    events = res.evidence.events
    chain_ok, bad_at, why = verify_chain(events)
    blob = json.dumps(events)
    leaked = [label for label, text in (("task", sc["task"]),
                                         ("final", sc.get("script", {}).get("final")),
                                         ("draft", sc.get("script", {}).get("draft")))
              if text and text in blob]
    types = {e["type"] for e in events}
    need = {"run_started", "input_screen", "usage", "decision"}
    if res.status == "completed":
        need |= {"council_round", "output_screen"}

    exp = sc["expect"]
    checks = []

    def check(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    deterministic = backend == "scripted" or exp["status"] == "blocked_at_input"
    if deterministic:
        check("status", res.status == exp["status"], f"{res.status} (expected {exp['status']})")
        check("decision", res.guard.decision == exp["decision"], f"{res.guard.decision} (expected {exp['decision']})")
        check("outcome", res.outcome == exp["outcome"], f"{res.outcome} (expected {exp['outcome']})")
        check("reason_codes", set(res.guard.reason_codes) == set(exp["reason_codes"]),
              f"{res.guard.reason_codes} (expected {exp['reason_codes']})")
        if "approvals" in exp:
            check("required_approvals", set(exp["approvals"]) <= set(res.guard.required_approvals),
                  f"{res.guard.required_approvals}")
        if "max_model_calls" in exp:
            check("model_calls", res.usage["model_calls"] <= exp["max_model_calls"],
                  f"{res.usage['model_calls']} (limit {exp['max_model_calls']})")
        if "withheld" in exp:
            check("withheld", res.withheld == exp["withheld"] and res.final_text is None, f"withheld={res.withheld}")
        if "outcome_after_first_review" in exp:
            check("outcome_after_first_review", len(outcomes) > 1 and outcomes[1] == exp["outcome_after_first_review"],
                  f"{outcomes}")
        check("no_review_errors", not review_errors, "; ".join(review_errors))
    check("evidence_chain_verifies", chain_ok, why if not chain_ok else f"{len(events)} events")
    check("no_raw_text_in_evidence", not leaked, ",".join(leaked) or "hash_only")
    check("required_events_present", need <= types, ",".join(sorted(need - types)) or "all present")
    if res.guard.decision == "allow":
        check("allow_has_no_reason_codes", not res.guard.reason_codes)

    return {"id": sc["id"], "kind": sc["kind"], "note": sc.get("note", ""), "deterministic": deterministic,
            "passed": all(c["ok"] for c in checks), "checks": checks, "outcomes": outcomes,
            "result": res.summary(), "events": events}


def write_report(out: Path, runs: list[dict], meta: dict) -> str:
    lines = [f"# RFAI governed council: acceptance run", "",
             f"- Runtime: {meta['runtime_version']}",
             f"- Policy: {meta['policy_id']} v{meta['policy_version']} (sha256 {meta['policy_sha256'][:16]}...)",
             f"- Scenario suite: {meta['suite']} v{meta['suite_version']}",
             f"- Backend: {meta['backend']}" + (" (scripted replies, no model: this tests the controls, not answer quality)"
                                                if meta["backend"] == "scripted" else ""),
             f"- Result: {meta['passed']} of {meta['checked']} pass/fail scenarios passed", "",
             "| Scenario | Kind | Status | Decision | Outcome | Reason codes | Model calls | Pass |",
             "|---|---|---|---|---|---|---|---|"]
    for r in runs:
        s = r["result"]
        lines.append(f"| {r['id']} | {r['kind']} | {s['status']} | {s['guard']['decision']} | {s['outcome']} | "
                     f"{', '.join(s['guard']['reason_codes']) or '-'} | {s['usage']['model_calls']} | "
                     f"{('yes' if r['passed'] else 'NO') if r['deterministic'] else 'observed'} |")
    lines += ["", "## Failed checks", ""]
    fails = [(r["id"], c) for r in runs for c in r["checks"] if not c["ok"]]
    lines += [f"- {i}: {c['check']}: {c['detail']}" for i, c in fails] or ["None."]
    lines += ["", "## Notes", ""] + [f"- {r['id']}: {r['note']}" for r in runs if r["note"]]
    lines += ["", "## What this does and does not show", "",
              "- It shows the policy screen, budgets, fail-safe handling, review routing and evidence log behave as specified on these scenarios.",
              "- It does not show that council answers are correct. `allow` means no rule matched and no council flag was raised.",
              "- The rules are a keyword and declared-capability screen. Wording the patterns do not cover will get through.",
              "- The evidence chain detects edits inside one exported log. It is not a signature; store the head hash separately."]
    text = "\n".join(lines) + "\n"
    (out / "acceptance_report.md").write_text(text)
    return text


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="discovery_demo")
    ap.add_argument("--scenarios", default=str(ROOT / "scenarios" / "discovery_acceptance_v1.json"))
    ap.add_argument("--policy", default=str(ROOT / "policies" / "discovery_default_v1.json"))
    ap.add_argument("--out", default=str(ROOT / "evidence_out"))
    ap.add_argument("--backend", choices=["scripted", "local"], default="scripted")
    ap.add_argument("--url", default="http://127.0.0.1:8080/v1/chat/completions")
    ap.add_argument("--only", default="", help="comma-separated scenario ids")
    ap.add_argument("--max-revisions", type=int, default=2)
    ap.add_argument("--real-clock", action="store_true", help="real timestamps (default: fixed, reproducible)")
    a = ap.parse_args(argv)

    policy = load_policy(a.policy)
    suite = json.loads(Path(a.scenarios).read_text())
    scen = suite["scenarios"]
    if a.only:
        keep = set(a.only.split(","))
        scen = [s for s in scen if s["id"] in keep]
    runs = [asyncio.run(run_scenario(s, policy, a.backend, a.url, not a.real_clock, a.max_revisions)) for s in scen]
    checked = [r for r in runs if r["deterministic"]]
    meta = {"runtime_version": RUNTIME_VERSION, "policy_id": policy.policy_id, "policy_version": policy.version,
            "policy_sha256": policy.sha256, "suite": suite["suite"], "suite_version": suite["version"],
            "backend": a.backend, "checked": len(checked), "passed": sum(r["passed"] for r in checked),
            "budget_defaults": dataclasses.asdict(ExecutionBudget())}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    pack = {"meta": meta, "runs": runs}
    pack_text = json.dumps(pack, indent=2, sort_keys=True)
    (out / "evidence_pack.json").write_text(pack_text + "\n")
    write_report(out, runs, meta)
    print(f"{meta['passed']}/{meta['checked']} pass/fail scenarios passed; "
          f"evidence pack sha256 {hashlib.sha256(pack_text.encode()).hexdigest()[:16]}; written to {out}")
    return 0 if meta["passed"] == meta["checked"] else 1


if __name__ == "__main__":
    sys.exit(main())
