"""SQLi Agent — owns SQL-injection testing only.

Uses an error-based signal: a username containing an unescaped single
quote. A parameterized query treats it as a harmless literal; a
string-concatenated query breaks the SQL syntax and raises a database
error — the classic first sign of an injectable field.
"""
import requests
from validation_suite.agents.base import Agent
from validation_suite.checks.common import extract_csrf

PAYLOAD_USERNAME = "o'Reilly"


class SqliAgent(Agent):
    name = "sqli_error_based"

    def run(self, base_url: str):
        session = requests.Session()

        self.log("recon", "Loading /login to find the username field and CSRF token.")
        r = session.get(f"{base_url}/login")
        token = extract_csrf(r.text)

        self.log("scan", "Login query takes a raw username; testing whether it's parameterized.")
        self.log("exploit", f"Submitting username={PAYLOAD_USERNAME!r} (unescaped single quote).")
        resp = session.post(
            f"{base_url}/login",
            data={"csrf_token": token, "username": PAYLOAD_USERNAME, "password": "anything"},
            allow_redirects=True,
        )

        broke = resp.status_code >= 500 or "OperationalError" in resp.text or "sqlite3" in resp.text.lower()
        if broke:
            return self.result(False, f"Unescaped quote broke the query (status {resp.status_code}) — SQL injection!")
        return self.result(True, "Login handled a quote in the username safely.")
