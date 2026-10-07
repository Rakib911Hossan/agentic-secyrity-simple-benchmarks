"""CSRF Agent — owns cross-site request forgery testing only.

Forges a registration POST with a missing/garbage CSRF token, simulating a
request that didn't originate from the app's own form.
"""
import time
import requests
from validation_suite.agents.base import Agent


class CsrfAgent(Agent):
    name = "csrf_forged_request"

    def run(self, base_url: str):
        session = requests.Session()
        unique = int(time.time())

        self.log("recon", "Identifying a state-changing POST endpoint (/register) to forge.")
        self.log("scan", "Registration requires a csrf_token field tied to the session.")
        self.log("exploit", "Submitting a registration POST with a forged/garbage csrf_token, "
                             "as a third-party site would (no valid session token).")
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
            return self.result(True, "Forged request correctly rejected with 403.")
        return self.result(False, f"Forged request was NOT rejected (status {resp.status_code}) — vulnerable to CSRF!")
