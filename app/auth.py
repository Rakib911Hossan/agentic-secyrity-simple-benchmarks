"""Registration, login, lockout, TOTP 2FA, and password recovery.

Secure mode: every query is parameterized and every password is bcrypt-hashed.
Vulnerable mode (MODE=vulnerable, localhost-only demo config) intentionally
swaps the login query for a string-concatenated one and skips lockout, so the
validation suite has something real to catch. Vulnerable mode must never be
enabled outside a local demo.
"""
import secrets
import hashlib
import base64
from io import BytesIO
from datetime import datetime, timedelta

import bcrypt
import pyotp
import qrcode
from cryptography.fernet import Fernet
from flask import Blueprint, request, session, redirect, url_for, render_template, current_app, flash

from app.db import get_db
from app.security import (
    validate_password_strength, generate_csrf_token, csrf_protect,
    device_fingerprint, is_secure_mode,
)
from app.ratelimit import rate_limit
from app.mailer import send_new_device_alert, send_password_reset
from app.audit import log_event

bp = Blueprint("auth", __name__)

LOCKOUT_THRESHOLD = 3
LOCKOUT_MINUTES = 5
RESET_TOKEN_MINUTES = 15


def _fernet() -> Fernet:
    return Fernet(current_app.config["FERNET_KEY"])


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _check_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


@bp.route("/register", methods=["GET", "POST"])
@csrf_protect
def register():
    if request.method == "GET":
        return render_template("register.html", csrf_token=generate_csrf_token())

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not username or not email or not password:
        flash("All fields are required.")
        return redirect(url_for("auth.register"))

    ok, msg = validate_password_strength(password)
    if not ok:
        flash(msg)
        return redirect(url_for("auth.register"))

    db = get_db()
    existing = db.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
    ).fetchone()
    if existing:
        flash("Username or email already registered.")
        return redirect(url_for("auth.register"))

    password_hash = _hash_password(password)
    db.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        (username, email, password_hash),
    )
    db.commit()
    log_event("user_registered", detail=username, ip=request.remote_addr)
    flash("Registration successful. Please log in.")
    return redirect(url_for("auth.login"))


@bp.route("/login", methods=["GET", "POST"])
@rate_limit(max_requests=15, window_seconds=60)
@csrf_protect
def login():
    if request.method == "GET":
        return render_template("login.html", csrf_token=generate_csrf_token())

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    db = get_db()

    if is_secure_mode():
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    else:
        # INTENTIONALLY VULNERABLE: string-concatenated query, demo-only,
        # used by the validation suite to prove SQLi is caught in secure mode.
        query = f"SELECT * FROM users WHERE username = '{username}'"
        user = db.execute(query).fetchone()

    if user is None:
        log_event("login_failed", detail=f"unknown user '{username}'", ip=request.remote_addr)
        flash("Invalid username or password.")
        return redirect(url_for("auth.login"))

    if is_secure_mode() and user["locked_until"]:
        locked_until = datetime.fromisoformat(user["locked_until"])
        if datetime.utcnow() < locked_until:
            flash(f"Account locked. Try again after {locked_until.strftime('%H:%M:%S')} UTC.")
            log_event("login_blocked_lockout", user_id=user["id"], ip=request.remote_addr)
            return redirect(url_for("auth.login"))

    password_ok = _check_password(password, user["password_hash"]) if password and user["password_hash"] else False

    if not password_ok:
        if is_secure_mode():
            attempts = user["failed_attempts"] + 1
            locked_until = None
            if attempts >= LOCKOUT_THRESHOLD:
                locked_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
            db.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            db.commit()
        log_event("login_failed", detail="bad password", user_id=user["id"], ip=request.remote_addr)
        flash("Invalid username or password.")
        return redirect(url_for("auth.login"))

    # Successful password check: reset failed-attempt counter.
    db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
    db.commit()

    if user["totp_enabled"]:
        session["pending_2fa_user_id"] = user["id"]
        return redirect(url_for("auth.verify_2fa"))

    _complete_login(user)
    return redirect(url_for("dashboard.index"))


@bp.route("/verify-2fa", methods=["GET", "POST"])
@csrf_protect
def verify_2fa():
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    if request.method == "GET":
        return render_template("verify_2fa.html", csrf_token=generate_csrf_token())

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    code = request.form.get("code", "").strip()

    secret = _fernet().decrypt(user["totp_secret_enc"].encode()).decode()
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        log_event("2fa_failed", user_id=user["id"], ip=request.remote_addr)
        flash("Invalid authentication code.")
        return redirect(url_for("auth.verify_2fa"))

    session.pop("pending_2fa_user_id", None)
    _complete_login(user)
    return redirect(url_for("dashboard.index"))


def _complete_login(user):
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["is_admin"] = bool(user["is_admin"])
    session.permanent = True

    db = get_db()
    fp = device_fingerprint()
    known = db.execute(
        "SELECT id FROM known_devices WHERE user_id = ? AND device_fingerprint = ?",
        (user["id"], fp),
    ).fetchone()
    if not known:
        db.execute(
            "INSERT INTO known_devices (user_id, device_fingerprint) VALUES (?, ?)",
            (user["id"], fp),
        )
        db.commit()
        send_new_device_alert(user["email"], user["username"], request.remote_addr or "unknown")
        log_event("new_device_login", user_id=user["id"], ip=request.remote_addr)

    log_event("login_success", user_id=user["id"], ip=request.remote_addr)


@bp.route("/setup-2fa", methods=["GET", "POST"])
@csrf_protect
def setup_2fa():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    if request.method == "GET":
        secret = pyotp.random_base32()
        session["pending_totp_secret"] = secret
        uri = pyotp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name="SecureGate")

        qr_img = qrcode.make(uri)
        buf = BytesIO()
        qr_img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        return render_template(
            "setup_2fa.html", secret=secret, otp_uri=uri, qr_b64=qr_b64,
            csrf_token=generate_csrf_token(),
        )

    code = request.form.get("code", "").strip()
    secret = session.get("pending_totp_secret")
    if not secret or not pyotp.TOTP(secret).verify(code, valid_window=1):
        flash("Invalid code. Try scanning the QR again.")
        return redirect(url_for("auth.setup_2fa"))

    enc = _fernet().encrypt(secret.encode()).decode()
    db.execute(
        "UPDATE users SET totp_secret_enc = ?, totp_enabled = 1 WHERE id = ?",
        (enc, user["id"]),
    )
    db.commit()
    session.pop("pending_totp_secret", None)
    log_event("2fa_enabled", user_id=user["id"], ip=request.remote_addr)
    flash("Two-factor authentication enabled.")
    return redirect(url_for("dashboard.index"))


@bp.route("/logout")
def logout():
    user_id = session.get("user_id")
    session.clear()
    log_event("logout", user_id=user_id, ip=request.remote_addr)
    return redirect(url_for("auth.login"))


@bp.route("/forgot-password", methods=["GET", "POST"])
@rate_limit(max_requests=5, window_seconds=300)
@csrf_protect
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html", csrf_token=generate_csrf_token())

    email = request.form.get("email", "").strip()
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    # Always show the same message, whether or not the email exists,
    # to avoid leaking which emails are registered.
    if user:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = (datetime.utcnow() + timedelta(minutes=RESET_TOKEN_MINUTES)).isoformat()
        db.execute(
            "INSERT INTO reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user["id"], token_hash, expires_at),
        )
        db.commit()
        reset_link = url_for("auth.reset_password", token=raw_token, _external=True)
        send_password_reset(user["email"], user["username"], reset_link)
        log_event("password_reset_requested", user_id=user["id"], ip=request.remote_addr)

    flash("If that email is registered, a reset link has been sent.")
    return redirect(url_for("auth.login"))


@bp.route("/reset-password/<token>", methods=["GET", "POST"])
@csrf_protect
def reset_password(token):
    db = get_db()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    row = db.execute(
        "SELECT * FROM reset_tokens WHERE token_hash = ? AND used = 0", (token_hash,)
    ).fetchone()

    if not row or datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
        flash("This reset link is invalid or has expired.")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "GET":
        return render_template("reset_password.html", token=token, csrf_token=generate_csrf_token())

    password = request.form.get("password", "")
    ok, msg = validate_password_strength(password)
    if not ok:
        flash(msg)
        return redirect(url_for("auth.reset_password", token=token))

    password_hash = _hash_password(password)
    db.execute("UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?",
               (password_hash, row["user_id"]))
    db.execute("UPDATE reset_tokens SET used = 1 WHERE id = ?", (row["id"],))
    db.commit()
    log_event("password_reset_completed", user_id=row["user_id"], ip=request.remote_addr)
    flash("Password updated. Please log in.")
    return redirect(url_for("auth.login"))
