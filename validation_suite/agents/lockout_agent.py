"""Lockout Agent — owns brute-force/lockout testing only.

Registers a disposable throwaway account (so it never touches real user
data or the shared admin account), fails its password 3 times, then
confirms a 4th attempt — even with the *correct* password — is blocked.
"""
import time
import requests
from validation_suite.agents.base import Agent
from validation_suite.checks.common import extract_csrf

TEST_PASSWORD = "Str0ng!Pass1"


class LockoutAgent(Agent):
    name = "lockout_after_3_attempts"

    def run(self, base_url: str):
        session = requests.Session()
        unique = int(time.time() * 1000) % 10_000_000
        username = f"lockout_test_{unique}"
        email = f"{username}@example.com"

        self.log("recon", "Registering a disposable test account, isolated from real/admin accounts.")
        r = session.get(f"{base_url}/register")
        token = extract_csrf(r.text)
        session.post(
            f"{base_url}/register",
            data={"csrf_token": token, "username": username, "email": email, "password": TEST_PASSWORD},
        )

        self.log("scan", "Login enforces a failed-attempt counter; testing the documented threshold of 3.")
        self.log("exploit", "Submitting 3 deliberately wrong passwords, then retrying with the correct one.")
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

        # Precise signals, not a bare "locked" substring search: the
        # dashboard also renders the global recent-activity table, which can
        # legitimately contain the word "locked" from unrelated events.
        logged_in = f"Hi, {username}" in final.text
        explicitly_locked = "Account locked." in final.text

        if logged_in:
            return self.result(False, "Correct password was accepted despite 3 prior failures — lockout not enforced!")
        if explicitly_locked:
            return self.result(True, "Account correctly locked after 3 failed attempts.")
        return self.result(False, "Unexpected response; lockout behavior could not be confirmed.")
