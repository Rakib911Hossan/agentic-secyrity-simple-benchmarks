"""Checks that a reflected XSS payload in the admin search box comes back
escaped, not as live markup. Requires an authenticated admin session."""
from .common import CheckResult

# No quote characters, so this check isolates XSS (output escaping) from
# any SQL-injection issue the search query might separately have.
PAYLOAD = "<img src=x onerror=alert(1)>"


def run(session, base_url) -> CheckResult:
    resp = session.get(f"{base_url}/admin/search", params={"q": PAYLOAD})

    if resp.status_code >= 500:
        return CheckResult("xss_reflected_search", False, f"Search errored (status {resp.status_code}); could not evaluate escaping.")
    if PAYLOAD in resp.text:
        return CheckResult("xss_reflected_search", False, "Payload reflected unescaped — vulnerable to XSS!")
    if "&lt;img" in resp.text:
        return CheckResult("xss_reflected_search", True, "Payload was HTML-escaped before being reflected.")
    return CheckResult("xss_reflected_search", True, "Payload did not appear verbatim in the response.")
