"""Checks the login form for SQL injection using an error-based signal: a
username containing an unescaped single quote. A parameterized query treats
it as a harmless literal (normal "invalid credentials" response); a
string-concatenated query breaks the SQL syntax and raises a database error
(a 500 response) — the classic first sign of an injectable field."""
from .common import CheckResult, extract_csrf

PAYLOAD_USERNAME = "o'Reilly"


def run(session, base_url) -> CheckResult:
    r = session.get(f"{base_url}/login")
    token = extract_csrf(r.text)
    resp = session.post(
        f"{base_url}/login",
        data={"csrf_token": token, "username": PAYLOAD_USERNAME, "password": "anything"},
        allow_redirects=True,
    )

    if resp.status_code >= 500 or "OperationalError" in resp.text or "sqlite3" in resp.text.lower():
        return CheckResult(
            "sqli_error_based", False,
            f"Unescaped quote broke the query (status {resp.status_code}) — SQL injection!",
        )
    return CheckResult("sqli_error_based", True, "Login handled a quote in the username safely.")
