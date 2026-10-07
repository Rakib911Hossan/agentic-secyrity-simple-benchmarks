"""Checks that an account locks after 3 consecutive failed login attempts.
Registers a disposable test user, fails its password 3 times, then confirms
a 4th attempt — even with the *correct* password — is blocked."""
import time
import requests

from .common import CheckResult, extract_csrf

TEST_PASSWORD = "Str0ng!Pass1"


def run(base_url: str) -> CheckResult:
    session = requests.Session()
    unique = int(time.time())
    username = f"lockout_test_{unique}"
    email = f"{username}@example.com"

    r = session.get(f"{base_url}/register")
    token = extract_csrf(r.text)
    session.post(
        f"{base_url}/register",
        data={"csrf_token": token, "username": username, "email": email, "password": TEST_PASSWORD},
    )

    for _ in range(3):
        r = session.get(f"{base_url}/login")
        token = extract_csrf(r.text)
        session.post(
            f"{base_url}/login",
            data={"csrf_token": token, "username": username, "password": "WrongPassword!1"},
        )

    r = session.get(f"{base_url}/login")
    token = extract_csrf(r.text)
    final = session.post(
        f"{base_url}/login",
        data={"csrf_token": token, "username": username, "password": TEST_PASSWORD},
        allow_redirects=True,
    )

    if "locked" in final.text.lower():
        return CheckResult("lockout_after_3_attempts", True, "Account correctly locked after 3 failed attempts.")
    if "Dashboard" in final.text or "/login" not in final.url:
        return CheckResult("lockout_after_3_attempts", False, "Correct password was accepted despite 3 prior failures — lockout not enforced!")
    return CheckResult("lockout_after_3_attempts", False, "Unexpected response; lockout behavior could not be confirmed.")
