#!/usr/bin/env python3
"""Validation suite entry point.

Runs a set of checks against this app's own locally-running instance and
writes a pass/fail report. This is a defensive QA tool, not a general
attack tool: it is hard-restricted to localhost (see checks/common.py) and
is meant to be run by the project author against their own dev server,
e.g.:

    MODE=vulnerable flask --app app run     # terminal 1 (demo weak mode)
    python validation_suite/runner.py       # terminal 2

Then flip MODE=secure and re-run to show the before/after.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

from validation_suite.checks.common import require_localhost
from validation_suite.checks import sqli, xss, csrf, headers, lockout

REPORT_DIR = Path(__file__).resolve().parent.parent / "report"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "ChangeMe!123"  # matches `flask seed-admin` default; change for real use


def run_all(base_url: str):
    require_localhost(base_url)
    results = []

    # Anonymous checks
    anon = requests.Session()
    results.append(sqli.run(anon, base_url))
    results.append(headers.run(anon, base_url))
    results.append(csrf.run(anon, base_url))

    # Authenticated (admin) checks
    admin = requests.Session()
    from validation_suite.checks.common import login
    login(admin, base_url, ADMIN_USERNAME, ADMIN_PASSWORD)
    results.append(xss.run(admin, base_url))

    # Lockout uses its own disposable session/user internally
    results.append(lockout.run(base_url))

    return results


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

    rows = "\n".join(
        f'<tr class="{"ok" if r.passed else "fail"}">'
        f"<td>{r.name}</td><td>{'PASS' if r.passed else 'FAIL'}</td><td>{r.detail}</td></tr>"
        for r in results
    )
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Validation Report</title>
<style>
body {{ font-family: system-ui, sans-serif; background:#0f172a; color:#e2e8f0; padding:2rem; }}
table {{ border-collapse: collapse; width:100%; }}
td, th {{ padding:0.5rem; border-bottom:1px solid #334155; text-align:left; }}
.ok {{ color:#4ade80; }}
.fail {{ color:#f87171; }}
</style></head>
<body>
<h1>SecureGate Validation Report</h1>
<p>Run at {timestamp} UTC — Mode: {mode_label} — {passed}/{total} checks passed</p>
<table>
<thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body></html>"""
    (REPORT_DIR / "validation_report.html").write_text(html)


def main():
    parser = argparse.ArgumentParser(description="Run SecureGate's security validation suite.")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--mode-label", default="unspecified", help="Label for the report, e.g. secure/vulnerable")
    args = parser.parse_args()

    results = run_all(args.base_url)
    write_report(results, args.mode_label)

    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"[{status}] {r.name}: {r.detail}")

    failed = sum(1 for r in results if not r.passed)
    print(f"\n{len(results) - failed}/{len(results)} checks passed.")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
