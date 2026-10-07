"""Checks that security-relevant response headers are present."""
from .common import CheckResult

REQUIRED_HEADERS = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]


def run(session, base_url) -> CheckResult:
    resp = session.get(f"{base_url}/login")
    missing = [h for h in REQUIRED_HEADERS if h not in resp.headers]

    if missing:
        return CheckResult("security_headers", False, f"Missing headers: {', '.join(missing)}")
    return CheckResult("security_headers", True, "All expected security headers are present.")
