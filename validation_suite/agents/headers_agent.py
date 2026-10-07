"""Headers Agent — owns HTTP security-header auditing only."""
import requests
from validation_suite.agents.base import Agent

REQUIRED_HEADERS = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]


class HeadersAgent(Agent):
    name = "security_headers"

    def run(self, base_url: str):
        session = requests.Session()

        self.log("recon", "Fetching /login to inspect the response headers.")
        resp = session.get(f"{base_url}/login")

        self.log("scan", f"Checking for: {', '.join(REQUIRED_HEADERS)}.")
        missing = [h for h in REQUIRED_HEADERS if h not in resp.headers]

        self.log("exploit", "N/A — this agent audits headers directly rather than exploiting a flaw.")
        if missing:
            return self.result(False, f"Missing headers: {', '.join(missing)}")
        return self.result(True, "All expected security headers are present.")
