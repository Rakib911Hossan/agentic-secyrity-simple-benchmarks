"""XSS Agent — owns reflected-XSS testing only.

Logs in as the admin itself (its own recon step) and probes the admin
search box with a quote-free payload, so this agent's verdict isolates
output-escaping from any separate SQL-injection issue in the same field.
"""
import requests
from validation_suite.agents.base import Agent
from validation_suite.checks.common import login

PAYLOAD = "<img src=x onerror=alert(1)>"


class XssAgent(Agent):
    name = "xss_reflected_search"

    def __init__(self, admin_username: str, admin_password: str):
        super().__init__()
        self.admin_username = admin_username
        self.admin_password = admin_password

    def run(self, base_url: str):
        session = requests.Session()

        self.log("recon", "Authenticating as admin to reach the search feature.")
        login(session, base_url, self.admin_username, self.admin_password)

        self.log("scan", "Admin search reflects the query back into the results page.")
        self.log("exploit", f"Submitting q={PAYLOAD!r} (quote-free, to isolate XSS from SQLi).")
        resp = session.get(f"{base_url}/admin/search", params={"q": PAYLOAD})

        if resp.status_code >= 500:
            return self.result(False, f"Search errored (status {resp.status_code}); could not evaluate escaping.")
        if PAYLOAD in resp.text:
            return self.result(False, "Payload reflected unescaped — vulnerable to XSS!")
        if "&lt;img" in resp.text:
            return self.result(True, "Payload was HTML-escaped before being reflected.")
        return self.result(True, "Payload did not appear verbatim in the response.")
