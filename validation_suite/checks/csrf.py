"""Checks that a state-changing POST without a valid CSRF token is rejected.
Uses the registration endpoint with a deliberately missing/garbage token."""
import time
from .common import CheckResult


def run(session, base_url) -> CheckResult:
    unique = int(time.time())
    resp = session.post(
        f"{base_url}/register",
        data={
            "csrf_token": "forged-or-missing-token",
            "username": f"csrf_test_{unique}",
            "email": f"csrf_test_{unique}@example.com",
            "password": "Str0ng!Pass",
        },
    )

    if resp.status_code == 403:
        return CheckResult("csrf_forged_request", True, "Forged request correctly rejected with 403.")
    return CheckResult(
        "csrf_forged_request", False,
        f"Forged request was NOT rejected (status {resp.status_code}) — vulnerable to CSRF!",
    )
