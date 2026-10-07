# SecureGate

A login/registration portal with an admin dashboard, built with layered
security defenses, plus a built-in **multi-agent security validation
suite**: five specialized agents (SQLi, XSS, CSRF, lockout, headers), each
owning one vulnerability class, run concurrently against the app's own
local instance and report whether each defense actually holds.

See [PLAN.md](PLAN.md) for the full project plan.

## Features
- Registration with a password-strength policy
- bcrypt password hashing
- Lockout after 3 failed login attempts
- TOTP-based two-factor authentication (QR setup)
- Password recovery via emailed, expiring, single-use tokens
- New-device login email alerts
- SQL injection / XSS / CSRF defenses
- Admin dashboard with safe search
- Hash-chained, tamper-evident audit log
- Per-IP rate limiting on login and password-reset requests
- A `MODE=secure|vulnerable` toggle and a multi-agent validation suite that
  proves the defenses work (and visibly fail when deliberately weakened)

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # edit SECRET_KEY etc. if desired
```

## Run
```bash
flask --app app run
flask --app app seed-admin   # creates admin / ChangeMe!123 (run once)
```

Visit http://127.0.0.1:5000

## Run the validation suite
Five agents run concurrently, each owning one vulnerability class:

| Agent | File | Checks |
|---|---|---|
| SqliAgent | `validation_suite/agents/sqli_agent.py` | SQL injection (error-based signal) |
| XssAgent | `validation_suite/agents/xss_agent.py` | Reflected XSS in admin search |
| CsrfAgent | `validation_suite/agents/csrf_agent.py` | Forged POST without a valid CSRF token |
| LockoutAgent | `validation_suite/agents/lockout_agent.py` | Brute-force lockout after 3 attempts |
| HeadersAgent | `validation_suite/agents/headers_agent.py` | Security response headers |

Each agent follows its own recon → scan → exploit → result loop and logs
every step, which the HTML report shows per agent.

With the app running locally (`MODE=secure` in `.env`, the default):
```bash
python -m validation_suite.runner --mode-label secure
```

To see the same checks catch real weaknesses, stop the server, set
`MODE=vulnerable` in `.env`, restart it, and re-run:
```bash
python -m validation_suite.runner --mode-label vulnerable
```

Reports are written to `report/validation_report.html` and `.json`.

**Scope note:** the validation suite only ever targets `127.0.0.1`/`localhost`
— it is a defensive QA tool for this app's own dev server, not a general
attack tool. Vulnerable mode exists purely for this local before/after demo
and must never be exposed outside localhost.
