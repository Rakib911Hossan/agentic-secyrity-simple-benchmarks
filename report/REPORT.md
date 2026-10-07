# SecureGate — Project Report

**Course:** Cyber Security Lab
**Team members:** [Name 1], [Name 2]
**Project option:** (i) Login/registration portal with admin dashboard and security measures

---

## 1. Introduction

SecureGate is a Flask-based login and admin dashboard application built to
demonstrate practical web-application security measures. Beyond the core
secure login flow, the project includes a `MODE=secure|vulnerable` toggle
and an automated **validation suite** that tests the app's own defenses
(SQL injection, XSS, CSRF, brute-force lockout, security headers) and
reports pass/fail — giving a live, reproducible before/after demonstration
of each vulnerability class and its fix.

[1–2 more sentences: motivation / why this project, if you want to add your own framing]

---

## 2. System Overview

- **Stack:** Python 3, Flask, SQLite, bcrypt, pyotp (TOTP), `cryptography`
  (Fernet), smtplib, requests (validation suite).
- **Architecture:** `app/` holds the Flask application (auth, dashboard,
  security middleware, DB, mailer, audit log); `validation_suite/` holds the
  independent test-runner and its checks.

**[SCREENSHOT 1: architecture/folder structure, or a simple diagram]**

---

## 3. Features & Security Measures

For each feature below: **what it does**, **the backend logic**, **the
security concept it maps to from the course**, and **a screenshot slot**.

### 3.1 Registration & Password Policy
- Enforces minimum 8 characters, upper/lower/digit/symbol.
- Server-side validation (never trust client-side only).

```python
# app/security.py
PASSWORD_RE = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$"
)

def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not PASSWORD_RE.match(password):
        return False, "Password needs an uppercase letter, a lowercase letter, a digit, and a symbol."
    return True, ""
```
**[SCREENSHOT 2: registration form + validation error example]**

### 3.2 Password Hashing (bcrypt)
Passwords are never stored in plaintext. bcrypt applies a per-user salt and
a slow, tunable hash — resistant to rainbow-table and brute-force attacks.

```python
# app/auth.py
def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def _check_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())
```
**[SCREENSHOT 3: users table row showing a bcrypt hash, e.g. via sqlite3 CLI]**

### 3.3 Account Lockout After 3 Failed Attempts
Failed attempts are counted per account; after 3, the account locks for 5
minutes, defeating simple brute-force/credential-stuffing attempts.

```python
# app/auth.py (login())
if not password_ok:
    attempts = user["failed_attempts"] + 1
    locked_until = None
    if attempts >= LOCKOUT_THRESHOLD:
        locked_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
    db.execute(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
        (attempts, locked_until, user["id"]),
    )
```
**[SCREENSHOT 4: "Account locked" message after 3 failed logins]**

### 3.4 Two-Factor Authentication (TOTP)
Time-based One-Time Passwords (RFC 6238) via an authenticator app. The
secret is encrypted at rest with Fernet (AES-128-CBC + HMAC) before being
stored, so even DB access alone doesn't expose it.

```python
# app/auth.py (setup_2fa() / verify_2fa())
secret = pyotp.random_base32()
enc = _fernet().encrypt(secret.encode()).decode()
...
totp = pyotp.TOTP(secret)
totp.verify(code, valid_window=1)
```
**[SCREENSHOT 5: QR code setup page]**
**[SCREENSHOT 6: 2FA code entry page during login]**

### 3.5 Password Recovery
A reset request generates a random token, stores only its SHA-256 hash in
the DB (so a DB leak doesn't leak usable tokens), and expires in 15
minutes. The same confirmation message is shown whether or not the email
exists, to avoid leaking which emails are registered.

```python
# app/auth.py (forgot_password())
raw_token = secrets.token_urlsafe(32)
token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
expires_at = (datetime.utcnow() + timedelta(minutes=RESET_TOKEN_MINUTES)).isoformat()
```
**[SCREENSHOT 7: forgot-password form + emailed/logged reset link]**

### 3.6 New-Device Login Alerts
Each login records a device fingerprint (IP + User-Agent). An unseen
fingerprint triggers an email alert and an audit-log entry.

```python
# app/auth.py (_complete_login())
fp = device_fingerprint()
known = db.execute(
    "SELECT id FROM known_devices WHERE user_id = ? AND device_fingerprint = ?",
    (user["id"], fp),
).fetchone()
if not known:
    ...
    send_new_device_alert(user["email"], user["username"], request.remote_addr)
```
**[SCREENSHOT 8: new-device alert email / console log output]**

### 3.7 SQL Injection Defense
All queries use parameterized placeholders (`?`), never string
concatenation, so user input is always treated as data, never as SQL code.

```python
# app/db.py — every query in the app follows this pattern:
db.execute("SELECT * FROM users WHERE username = ?", (username,))
```
**[SCREENSHOT 9: validation suite SQLi check — PASS in secure mode]**

### 3.8 XSS (Cross-Site Scripting) Defense
Jinja2 auto-escapes all template output by default, and a strict
Content-Security-Policy header further restricts what scripts can run.

```python
# app/security.py
response.headers["Content-Security-Policy"] = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
)
```
**[SCREENSHOT 10: validation suite XSS check — PASS in secure mode]**

### 3.9 CSRF Defense
Every state-changing form includes a per-session CSRF token, checked with a
constant-time comparison before the request is processed.

```python
# app/security.py
def csrf_protect(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method == "POST" and is_secure_mode():
            sent = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not sent or not expected or not secrets.compare_digest(sent, expected):
                abort(403, description="Invalid or missing CSRF token.")
        return view(*args, **kwargs)
    return wrapped
```
**[SCREENSHOT 11: validation suite CSRF check — PASS in secure mode]**

### 3.10 Rate Limiting
A per-IP sliding-window limiter caps login attempts (30/min) and
password-reset requests (5/5min), slowing automated brute-force/enumeration.

```python
# app/ratelimit.py
while bucket and now - bucket[0] > window_seconds:
    bucket.popleft()
if len(bucket) >= max_requests:
    abort(429, description="Too many requests. Please slow down and try again shortly.")
```
**[SCREENSHOT 12: a 429 response after a burst of login attempts]**

### 3.11 Admin Dashboard with Safe Search
The admin search box uses the same parameterized-query pattern, with input
length capped, so it cannot be used for SQL injection or data exfiltration
via `LIKE` wildcards abuse.

**[SCREENSHOT 13: admin dashboard, search in action]**

### 3.12 Hash-Chained, Tamper-Evident Audit Log
Each audit-log entry stores `sha256(prev_hash + event + detail + timestamp)`.
Recomputing the chain from the first entry detects any later edit or
deletion — a lightweight integrity mechanism inspired by blockchain-style
hash chaining, directly tying into the course's hashing topic.

```python
# app/audit.py
def _hash_entry(prev_hash, event, detail, created_at) -> str:
    payload = f"{prev_hash}|{event}|{detail}|{created_at}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
```
**[SCREENSHOT 14: "Verify audit log integrity" page showing VERIFIED]**

### 3.13 Security Activity Dashboard Chart
Admins see a live chart of login successes/failures, lockouts, new-device
logins, 2FA failures and reset requests, pulled from the audit log.

**[SCREENSHOT 15: dashboard activity chart]**

---

## 4. The Multi-Agent Validation Suite — Before/After Demonstration

The standout feature of this project: a `MODE=secure|vulnerable` toggle and
**five specialized agents**, each owning exactly one vulnerability class,
coordinated by `validation_suite/runner.py`. This proves each defense
actually works, rather than just asserting it in writing.

**How it works:** each agent (`validation_suite/agents/*.py`) runs its own
recon → scan → exploit → result loop — independent HTTP session, its own
reasoning steps logged — against the app's own local server. The
coordinator dispatches all five agents **concurrently** via a thread pool,
so "multiple agents working" is literal: each one probes its target
independently and reports back on its own timeline, not in a fixed
sequence. Their verdicts are merged into one pass/fail report at
`report/validation_report.html`, which also shows each agent's full
recon/scan/exploit trace.

| Agent | Vulnerability class |
|---|---|
| `SqliAgent` | SQL injection (error-based signal on an unescaped quote) |
| `XssAgent` | Reflected XSS in the admin search field |
| `CsrfAgent` | Forged POST without a valid CSRF token |
| `LockoutAgent` | Brute-force lockout after 3 failed attempts |
| `HeadersAgent` | Missing security response headers |

**Secure mode result:**

```
[PASS] sqli_error_based: Login handled a quote in the username safely.
[PASS] security_headers: All expected security headers are present.
[PASS] csrf_forged_request: Forged request correctly rejected with 403.
[PASS] xss_reflected_search: Payload was HTML-escaped before being reflected.
[PASS] lockout_after_3_attempts: Account correctly locked after 3 failed attempts.

5/5 agents reported PASS.
```

**Vulnerable mode result** (same checks, against intentionally weakened
code paths in `app/auth.py` and `app/dashboard.py`):

```
[FAIL] sqli_error_based: Unescaped quote broke the query (status 500) — SQL injection!
[FAIL] security_headers: Missing headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options
[FAIL] csrf_forged_request: Forged request was NOT rejected (status 200) — vulnerable to CSRF!
[FAIL] xss_reflected_search: Payload reflected unescaped — vulnerable to XSS!
[FAIL] lockout_after_3_attempts: Correct password was accepted despite 3 prior failures — lockout not enforced!

0/5 agents reported PASS.
```

**[SCREENSHOT 16: validation_report.html rendered in a browser, secure mode —
include the per-agent recon/scan/exploit step trace]**
**[SCREENSHOT 17: validation_report.html rendered in a browser, vulnerable mode]**

This demonstrates, with reproducible evidence rather than just a written
claim, that each specific defense (parameterized queries, output escaping,
CSRF tokens, lockout logic, security headers) is the thing actually
stopping the corresponding attack — and that it holds up even when five
independent agents are probing it at the same time.

---

## 5. Testing & Validation Summary

| Defense | Secure mode | Vulnerable mode |
|---|---|---|
| SQL injection | PASS | FAIL |
| XSS | PASS | FAIL |
| CSRF | PASS | FAIL |
| Brute-force lockout | PASS | FAIL |
| Security headers | PASS | FAIL |

Additional manual checks performed:
- 20-request login burst → rate limiter returns HTTP 429 after the 15th POST.
- Hash-chain integrity check verified across [N] real audit log entries.

---

## 6. Challenges & Limitations

- The in-memory rate limiter resets on server restart and doesn't scale
  across multiple worker processes (would need Redis in production).
- SMS alerts were out of scope; email alerts only (with a console fallback
  for offline demos).
- [Add any team-specific challenges you hit while building/demoing]

---

## 7. Conclusion

[2–4 sentences: what you learned, how the project maps to course concepts
— hashing, symmetric encryption, authentication, common web vulnerabilities
— and what you'd extend given more time.]

---

## Appendix: How to Reproduce

See [README.md](../README.md) for setup/run instructions. In short:

```bash
flask --app app seed-admin
flask --app app run                              # secure mode (default)
python -m validation_suite.runner --mode-label secure

MODE=vulnerable flask --app app run              # restart in vulnerable mode
python -m validation_suite.runner --mode-label vulnerable
```
