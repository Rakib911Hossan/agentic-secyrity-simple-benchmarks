# Project Plan: SecureGate — Login Portal with Built-in Security Validation Suite

## Overview
A secure login/registration web app with an admin dashboard (Option i from the
assignment), built with layered security defenses, plus a standout feature: an
automated **security validation suite** that tests the app's own defenses
(SQLi, XSS, CSRF, lockout, cookie flags, etc.) and produces a pass/fail report.
The suite runs only against this app's own local instance — it is a defensive
QA tool, not a general-purpose attack tool.

**Stack:** Python 3, Flask, SQLite, `bcrypt`, `pyotp` (TOTP 2FA),
`cryptography` (Fernet), `smtplib` (email), `requests` (validation suite).
Plain HTML/CSS/JS frontend.

## Folder Structure
```
cyber_security_lab_project/
├── app/
│   ├── __init__.py        # app factory, mode config (secure/vulnerable)
│   ├── auth.py            # register, login, logout, lockout, 2FA, recovery
│   ├── dashboard.py       # admin dashboard + search
│   ├── security.py        # CSRF, headers, validation, rate limit
│   ├── db.py              # SQLite helpers (safe + toggleable unsafe mode)
│   ├── mailer.py          # email alerts / OTP / reset links
│   ├── audit.py           # hash-chained audit log
│   ├── templates/ static/
├── validation_suite/
│   ├── runner.py          # orchestrates checks, produces report
│   └── checks/            # sqli.py, xss.py, csrf.py, lockout.py, headers.py
├── tests/
├── report/                # screenshots, report draft
├── requirements.txt
└── README.md
```

## Stage 1: Core App (~40% effort)
| Feature | Approach |
|---|---|
| Registration | Min 8 chars, upper/lower/digit/symbol, server-side validation |
| Password hashing | bcrypt, per-user salt |
| Login | Generic error message (no account-existence leak) |
| Lockout | 3 failed attempts → 5-minute lock, counters in DB |
| 2FA | TOTP via authenticator app, secret encrypted with Fernet, QR setup |
| Password recovery | Emailed single-use token, hashed in DB, 15-minute expiry |
| New-device alert | Device fingerprint (user-agent + IP) stored; new one emails alert |
| SQL injection defense | Parameterized queries everywhere |
| XSS defense | Jinja auto-escaping, CSP header, HttpOnly cookies |
| CSRF defense | Per-session token on every POST |
| Admin dashboard | Role check, user list, parameterized/limited search |
| Sessions | Secure + SameSite cookies, 15-minute idle timeout |

## Stage 2: Signature Feature — Validation Suite (~35% effort)
1. **Mode switch:** `MODE=secure|vulnerable` in config (vulnerable mode
   intentionally weakens one layer at a time — string-concatenated SQL, no
   escaping, no CSRF check, no lockout — bound to localhost only, clearly
   bannered).
2. **Validation suite**, following a recon → scan → check → report loop:
   - **Recon:** crawl pages/forms of the local app.
   - **Scan:** enumerate inputs and endpoints to test.
   - **Check:** run each module (SQLi payload rejection, XSS payload
     escaping, CSRF token enforcement, lockout after 3 attempts, cookie/CSP
     header presence).
   - **Report:** pass/fail per check with evidence, written to HTML/JSON and
     shown on the dashboard.
3. **Demo flow:** run suite against vulnerable mode (checks fail, showing the
   gap), flip to secure mode, run again (checks pass) — a clear before/after
   demonstration for presentation and viva.

## Stage 3: Polish (~15%, optional if time allows)
- Hash-chained audit log (each entry hashes the previous) with an
  "verify integrity" button.
- Dashboard charts: failed logins, lockouts, check results over time.
- Per-IP rate limiting.

## Stage 4: Report & Presentation (~10%)
- **Report:** per feature — backend code excerpt, screenshot, short
  explanation of the security logic — plus a before/after validation table.
- **Slides (pptx):** problem statement, architecture, live demo script, and a
  viva cheat-sheet (why bcrypt, how TOTP works, how each defense works).

## Build Order
1. Project skeleton + database schema
2. Register, login, bcrypt
3. Lockout, validation, sessions
4. CSRF, headers, XSS protection
5. TOTP 2FA
6. Email: recovery + new-device alert
7. Admin dashboard + search
8. Vulnerable/secure mode toggle
9. Validation suite checks + report
10. Polish, tests, README

## Default Decisions (flag if you disagree)
- **Email:** Gmail SMTP app password, with console/file fallback for offline
  demos. SMS is out of scope.
- **Database:** SQLite, single file, zero setup.
- **Safety scope:** validation suite only ever targets `localhost`/the app's
  own instance; no external or third-party targets.
