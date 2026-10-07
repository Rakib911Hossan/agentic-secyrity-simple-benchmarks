"""Admin dashboard: user list, search, audit log view, mode toggle, and the
validation-suite trigger/report viewer."""
from flask import Blueprint, request, render_template, session, current_app

from app.db import get_db
from app.security import generate_csrf_token, csrf_protect, login_required, is_secure_mode
from app.audit import verify_chain

bp = Blueprint("dashboard", __name__)


TRACKED_EVENTS = [
    "login_success", "login_failed", "login_blocked_lockout",
    "new_device_login", "2fa_failed", "password_reset_requested",
]


@bp.route("/")
@login_required()
def index():
    db = get_db()
    recent_events = db.execute(
        "SELECT event, detail, ip, created_at FROM audit_log ORDER BY id DESC LIMIT 20"
    ).fetchall()

    counts = {}
    if session.get("is_admin"):
        rows = db.execute(
            "SELECT event, COUNT(*) AS n FROM audit_log GROUP BY event"
        ).fetchall()
        counts = {r["event"]: r["n"] for r in rows}
        counts = {e: counts.get(e, 0) for e in TRACKED_EVENTS}

    max_count = max(counts.values()) if counts and max(counts.values()) > 0 else 1

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        is_admin=session.get("is_admin"),
        recent_events=recent_events,
        secure_mode=is_secure_mode(),
        event_counts=counts,
        max_count=max_count,
    )


@bp.route("/admin/search")
@login_required(admin_only=True)
def search():
    query = request.args.get("q", "").strip()
    db = get_db()

    if is_secure_mode() or not query:
        # Parameterized query + length cap: safe against SQL injection.
        rows = db.execute(
            "SELECT id, username, email, is_admin FROM users "
            "WHERE username LIKE ? OR email LIKE ? LIMIT 50",
            (f"%{query[:100]}%", f"%{query[:100]}%"),
        ).fetchall()
    else:
        # INTENTIONALLY VULNERABLE: string-concatenated LIKE query, demo-only.
        like = f"%{query}%"
        sql = f"SELECT id, username, email, is_admin FROM users WHERE username LIKE '{like}' OR email LIKE '{like}'"
        rows = db.execute(sql).fetchall()

    return render_template(
        "search_results.html", query=query, rows=rows,
        secure_mode=is_secure_mode(), csrf_token=generate_csrf_token(),
    )


@bp.route("/admin/audit/verify")
@login_required(admin_only=True)
def verify_audit():
    ok, message = verify_chain()
    return render_template("audit_verify.html", ok=ok, message=message, csrf_token=generate_csrf_token())
