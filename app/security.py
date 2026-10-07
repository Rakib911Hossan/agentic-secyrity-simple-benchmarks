"""Cross-cutting security: CSRF tokens, response headers, password policy,
and the secure/vulnerable mode switch used for the validation-suite demo."""
import re
import secrets
from functools import wraps
from flask import session, request, abort, current_app, g

PASSWORD_RE = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$"
)


def is_secure_mode() -> bool:
    return current_app.config.get("MODE", "secure") == "secure"


def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not PASSWORD_RE.match(password):
        return False, "Password needs an uppercase letter, a lowercase letter, a digit, and a symbol."
    return True, ""


def generate_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def csrf_protect(view):
    """Rejects POSTs whose csrf_token doesn't match the session's token.
    In vulnerable mode this check is skipped, to demonstrate the gap."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method == "POST" and is_secure_mode():
            sent = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not sent or not expected or not secrets.compare_digest(sent, expected):
                abort(403, description="Invalid or missing CSRF token.")
        return view(*args, **kwargs)
    return wrapped


def apply_security_headers(response):
    """Sets security headers on every response. CSP + X-Frame-Options help
    defend against XSS/clickjacking; these are relaxed in vulnerable mode."""
    if is_secure_mode():
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
    return response


def device_fingerprint() -> str:
    ua = request.headers.get("User-Agent", "unknown")
    ip = request.remote_addr or "unknown"
    return f"{ip}|{ua}"


def login_required(admin_only: bool = False):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                abort(401, description="Login required.")
            if admin_only and not session.get("is_admin"):
                abort(403, description="Admin access required.")
            return view(*args, **kwargs)
        return wrapped
    return decorator
