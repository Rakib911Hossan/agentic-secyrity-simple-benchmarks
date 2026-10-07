# SecureGate — Presentation Outline (for .pptx)

Target: ~10-12 slides, 8-10 min talk + demo. One slide per bullet group below.

1. **Title slide** — SecureGate: a login portal that tests its own defenses.
   Team names, course, date.

2. **Problem / motivation** — Why login security matters; the assignment's
   requirement list (hashing, 2FA, lockout, SQLi/XSS/CSRF, etc.).

3. **Architecture** — One diagram: Flask app (auth/dashboard/security/db/
   mailer/audit) + the separate validation_suite — five independent agents
   coordinated by a thread-pool runner — that tests it over HTTP.
   Mention the stack (Flask, SQLite, bcrypt, pyotp, Fernet).

4. **Feature walkthrough 1: Account security**
   — Registration + password policy, bcrypt hashing, lockout after 3
   attempts. Screenshot: lockout message.

5. **Feature walkthrough 2: 2FA & recovery**
   — TOTP QR setup, password reset via expiring token, new-device email
   alert. Screenshot: QR code + 2FA prompt.

6. **Feature walkthrough 3: Attack defenses**
   — SQL injection (parameterized queries), XSS (auto-escaping + CSP),
   CSRF (per-session token), rate limiting. One code snippet per defense
   (keep short, 3-5 lines).

7. **The signature feature: a multi-agent validation suite**
   — Explain the MODE=secure|vulnerable toggle and why you built it (prove
   the defenses work, not just claim it). Then explain the 5 agents: each
   owns one vulnerability class, runs its own recon → scan → exploit loop
   with its own HTTP session, and all 5 run **concurrently** via a thread
   pool — show the agent table (Sqli/Xss/Csrf/Lockout/Headers).

8. **LIVE DEMO: vulnerable mode**
   — Run the suite against vulnerable mode on screen; show the FAIL report
   (SQLi error, XSS reflected, CSRF accepted, no lockout, missing headers).

9. **LIVE DEMO: secure mode**
   — Flip the switch, re-run the suite; show 5/5 PASS. This is the
   before/after moment — make it visual (the HTML report page is good for
   this).

10. **Audit log & dashboard** — Hash-chained tamper-evident log + the
    activity chart. Tie the hash chain to the course's hashing topic
    explicitly (sha256, chained like a mini blockchain).

11. **Challenges & what we'd add next** — Rate limiter scaling, SMS alerts,
    anything your team actually struggled with (be honest, examiners like
    this).

12. **Q&A / viva readiness slide** — One slide listing the "ask me about"
    topics you're most prepared to defend: bcrypt vs plain hashing, TOTP
    math, why parameterized queries stop SQLi, CSRF token theory, hash
    chains for tamper evidence.

## Viva cheat-sheet (memorize, don't read off this)

- **Why bcrypt not SHA-256 for passwords?** bcrypt is deliberately slow and
  has a built-in per-hash salt and a tunable cost factor, so brute-forcing
  many password guesses is expensive; a fast hash like SHA-256 is meant for
  speed and is bad for passwords.
- **How does TOTP work?** HMAC of a shared secret + the current 30-second
  time step, truncated to 6 digits. Server and app independently compute
  the same code because both know the secret and agree on time.
- **Why does parameterizing SQL stop injection?** The query structure is
  sent to the DB separately from the data; user input is bound as a typed
  value, never concatenated into the SQL text, so it can't change the
  query's meaning.
- **Why does a CSRF token stop forged requests?** The token proves the
  request came from a page the app itself served (it knows the session's
  token); a third-party site making a forged request has no way to read or
  guess that token.
- **What does the hash chain in the audit log actually protect against?**
  Not preventing tampering, but *detecting* it after the fact — changing
  any past entry changes its hash, which breaks every hash after it, so
  recomputing the chain from the start reveals exactly where it was altered.
