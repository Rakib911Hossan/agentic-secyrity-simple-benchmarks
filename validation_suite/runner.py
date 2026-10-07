#!/usr/bin/env python3
"""Coordinator for the specialized validation agents.

Each agent (validation_suite/agents/) owns exactly one vulnerability class
and runs independently, with its own HTTP session, against this app's own
locally-running instance. The coordinator dispatches all agents
concurrently via a thread pool — "multiple agents working" is literal: each
one does its own recon -> scan -> exploit and reports back on its own
timeline, and their results are merged into a single pass/fail report.

This is a defensive QA tool, not a general attack tool: it is
hard-restricted to localhost (see checks/common.py) and is meant to be run
by the project author against their own dev server, e.g.:

    MODE=vulnerable flask --app app run     # terminal 1 (demo weak mode)
    python -m validation_suite.runner        # terminal 2

Then flip MODE=secure and re-run to show the before/after.
"""
import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from validation_suite.checks.common import require_localhost
from validation_suite.agents.sqli_agent import SqliAgent
from validation_suite.agents.xss_agent import XssAgent
from validation_suite.agents.csrf_agent import CsrfAgent
from validation_suite.agents.lockout_agent import LockoutAgent
from validation_suite.agents.headers_agent import HeadersAgent

REPORT_DIR = Path(__file__).resolve().parent.parent / "report"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "ChangeMe!123"  # matches `flask seed-admin` default; change for real use


def build_agents():
    return [
        SqliAgent(),
        HeadersAgent(),
        CsrfAgent(),
        XssAgent(ADMIN_USERNAME, ADMIN_PASSWORD),
        LockoutAgent(),
    ]


def run_all(base_url: str):
    require_localhost(base_url)
    agents = build_agents()

    results = []
    # Each agent owns its own session/state, so running them concurrently
    # is safe — this is what makes "multiple agents working" real rather
    # than just sequential calls with different labels.
    with ThreadPoolExecutor(max_workers=len(agents)) as pool:
        futures = {pool.submit(agent.run, base_url): agent for agent in agents}
        for future in as_completed(futures):
            agent = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # an agent crashing is itself a finding
                results.append(_crash_result(agent, exc))
    # Keep a stable, readable order in the report regardless of completion order.
    order = {a.name: i for i, a in enumerate(agents)}
    results.sort(key=lambda r: order.get(r.name, 99))
    return results


def _crash_result(agent, exc):
    from validation_suite.checks.common import CheckResult
    return CheckResult(agent.name, False, f"Agent crashed: {exc!r}", steps=agent.steps)


def write_report(results, mode_label: str):
    REPORT_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).isoformat()
    passed = sum(1 for r in results if r.passed)
    total = len(results)

    data = {
        "timestamp": timestamp,
        "mode_label": mode_label,
        "passed": passed,
        "total": total,
        "results": [r.to_dict() for r in results],
    }
    (REPORT_DIR / "validation_report.json").write_text(json.dumps(data, indent=2))

    def steps_html(steps):
        if not steps:
            return ""
        items = "".join(f"<li><strong>{s['stage']}:</strong> {s['message']}</li>" for s in steps)
        return f"<ul class='steps'>{items}</ul>"

    rows = "\n".join(
        f'<tr class="{"ok" if r.passed else "fail"}">'
        f"<td>{r.name}</td><td>{'PASS' if r.passed else 'FAIL'}</td>"
        f"<td>{r.detail}{steps_html(r.steps)}</td></tr>"
        for r in results
    )
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Validation Report</title>
<style>
body {{ font-family: system-ui, sans-serif; background:#0f172a; color:#e2e8f0; padding:2rem; }}
table {{ border-collapse: collapse; width:100%; }}
td, th {{ padding:0.5rem; border-bottom:1px solid #334155; text-align:left; vertical-align: top; }}
.ok {{ color:#4ade80; }}
.fail {{ color:#f87171; }}
.steps {{ margin: 0.4rem 0 0; padding-left: 1.2rem; color:#94a3b8; font-size: 0.85rem; }}
</style></head>
<body>
<h1>SecureGate Validation Report</h1>
<p>Run at {timestamp} — Mode: {mode_label} — {passed}/{total} agents reported PASS</p>
<p>{total} specialized agents ran concurrently, each owning one vulnerability class.</p>
<table>
<thead><tr><th>Agent</th><th>Result</th><th>Detail &amp; reasoning</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body></html>"""
    (REPORT_DIR / "validation_report.html").write_text(html)


def main():
    parser = argparse.ArgumentParser(description="Run SecureGate's specialized validation agents.")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--mode-label", default="unspecified", help="Label for the report, e.g. secure/vulnerable")
    args = parser.parse_args()

    results = run_all(args.base_url)
    write_report(results, args.mode_label)

    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"[{status}] {r.name}: {r.detail}")

    failed = sum(1 for r in results if not r.passed)
    print(f"\n{len(results) - failed}/{len(results)} agents reported PASS.")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
