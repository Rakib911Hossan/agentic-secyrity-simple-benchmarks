"""Unified entry point for the dashboard's "Attacker view" attack menu.

The user picks one attack; this dispatches it and streams its steps to the
same agent_runs/agent_steps tables the live dashboard timeline polls.

Two kinds of attack share that one live view:
  - "llm": the Gemini-driven autonomous agent (currently the SQL-injection
    login bypass) — it decides its own payloads and captures the admin flag.
  - "scripted": one of the deterministic validation agents
    (validation_suite/agents/) — reliable, fast, and already step-logged.

Each attack also carries a short human writeup (what it is, how it works,
how the app defends against it) that the Attacker view shows beside the run.
"""
from pathlib import Path

from validation_suite.llm_agent import AgentStore, run_llm_agent, DEFAULT_MODEL
from validation_suite.agents.xss_agent import XssAgent
from validation_suite.agents.csrf_agent import CsrfAgent
from validation_suite.agents.lockout_agent import LockoutAgent
from validation_suite.agents.headers_agent import HeadersAgent

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "ChangeMe!123"


# Attack catalogue. `kind` picks the runner; `scripted_factory` builds the
# scripted agent when kind == "scripted".
ATTACKS = {
    "sqli_login": {
        "title": "SQL injection — login auth bypass",
        "kind": "llm",
        "blurb": "An autonomous LLM agent injects a forged admin row into the "
                 "login query and captures the admin-only flag.",
        "defense": "Parameterized queries (placeholders, never string "
                   "concatenation) make the input pure data — the quote and "
                   "UNION are treated as a literal username, so the injection "
                   "collapses to a harmless failed login.",
    },
    "xss_search": {
        "title": "Reflected XSS — admin search",
        "kind": "scripted",
        "scripted_factory": lambda: XssAgent(ADMIN_USERNAME, ADMIN_PASSWORD),
        "blurb": "Submits a <script> payload to the admin search and checks "
                 "whether it is reflected unescaped.",
        "defense": "Jinja auto-escaping plus a Content-Security-Policy header "
                   "turn the payload into inert text instead of executable "
                   "script.",
    },
    "csrf_forged": {
        "title": "CSRF — forged state-changing request",
        "kind": "scripted",
        "scripted_factory": CsrfAgent,
        "blurb": "Sends a POST with a missing/garbage CSRF token, as a "
                 "third-party site would.",
        "defense": "A per-session CSRF token required on every POST; a request "
                   "without the matching token is rejected with 403.",
    },
    "lockout_bruteforce": {
        "title": "Brute force — account lockout",
        "kind": "scripted",
        "scripted_factory": LockoutAgent,
        "blurb": "Fails login 3 times then checks whether a 4th attempt — even "
                 "with the correct password — is blocked.",
        "defense": "A per-account failed-attempt counter locks the account for "
                   "5 minutes after 3 failures, defeating online guessing.",
    },
    "headers_audit": {
        "title": "Security headers audit",
        "kind": "scripted",
        "scripted_factory": HeadersAgent,
        "blurb": "Checks that CSP, X-Frame-Options and X-Content-Type-Options "
                 "are present on responses.",
        "defense": "Every response sets these headers in secure mode, "
                   "hardening against XSS, clickjacking and MIME sniffing.",
    },
}


def run_attack(attack_id: str, base_url: str, store: AgentStore, run_id: str,
               mode_label: str, api_key: str | None = None, model: str | None = None):
    """Runs the chosen attack against base_url, writing steps to `store`
    under the pre-created `run_id`. Blocking; call from a background thread."""
    spec = ATTACKS.get(attack_id)
    if spec is None:
        store.log(run_id, "giveup", f"Unknown attack '{attack_id}'.")
        store.finish(run_id, "failed", f"Unknown attack '{attack_id}'.")
        return

    if spec["kind"] == "llm":
        run_llm_agent(base_url, mode_label, api_key, model or DEFAULT_MODEL, store, run_id=run_id)
        return

    # scripted agent: run it and mirror its recon/scan/exploit/result steps
    agent = spec["scripted_factory"]()
    store.log(run_id, "recon", f"Launching scripted {agent.__class__.__name__} against {base_url}.")
    try:
        result = agent.run(base_url)
    except Exception as exc:
        store.log(run_id, "giveup", f"Scripted agent crashed: {exc!r}")
        store.finish(run_id, "failed", str(exc))
        return

    for step in result.steps:
        store.log(run_id, step.get("stage", "scan"), step.get("message", ""))

    # A scripted agent PASS means the defense held (attack was blocked). In
    # attacker terms that's a failed attack; in vulnerable mode the defense
    # is down and the agent reports the weakness (passed=False).
    if result.passed:
        store.finish(run_id, "defended", f"Defense held: {result.detail}")
    else:
        store.finish(run_id, "breached", f"Weakness found: {result.detail}")
