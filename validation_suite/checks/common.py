"""Shared helpers for validation-suite checks. All checks target localhost
only — this suite tests this app's own running instance, nothing else."""
import re
import urllib.parse

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


class CheckResult:
    def __init__(self, name: str, passed: bool, detail: str, steps: list | None = None):
        self.name = name
        self.passed = passed
        self.detail = detail
        self.steps = steps or []  # [{"stage": "recon"|"scan"|"exploit"|"result", "message": str}]

    def to_dict(self):
        return {"name": self.name, "passed": self.passed, "detail": self.detail, "steps": self.steps}


def require_localhost(base_url: str):
    host = urllib.parse.urlparse(base_url).hostname
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError(
            f"Refusing to run validation suite against non-local host '{host}'. "
            "This suite only tests this app's own local instance."
        )


def extract_csrf(html: str) -> str:
    m = CSRF_RE.search(html)
    return m.group(1) if m else ""


def login(session, base_url, username, password):
    """Logs in with username/password, returns the final response."""
    r = session.get(f"{base_url}/login")
    token = extract_csrf(r.text)
    return session.post(
        f"{base_url}/login",
        data={"csrf_token": token, "username": username, "password": password},
        allow_redirects=True,
    )
