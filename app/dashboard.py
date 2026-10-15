"""Admin dashboard: user list, search, audit log view, mode toggle, and the
validation-suite trigger/report viewer."""
import os
import threading
from pathlib import Path

from flask import Blueprint, request, render_template, session, current_app, redirect, url_for, flash, abort, jsonify

from app.db import get_db
from app.security import generate_csrf_token, csrf_protect, login_required, is_secure_mode
from app.audit import verify_chain, log_event

bp = Blueprint("dashboard", __name__)


TRACKED_EVENTS = [
    "login_success", "login_failed", "login_blocked_lockout",
    "new_device_login", "2fa_failed", "password_reset_requested",
]


def compute_posture():
    """A live 0–100 security-posture score built from which defenses are
    actually active right now. Mode-gated defenses (SQLi/CSRF/headers/rate
    limit/lockout) go dark in vulnerable mode, so the score visibly collapses
    — a one-number demonstration of what the defenses are worth."""
    secure = is_secure_mode()
    db = get_db()
    chain_ok, _ = verify_chain()
    twofa = db.execute("SELECT COUNT(*) AS n FROM users WHERE totp_enabled = 1").fetchone()["n"]

    factors = [
        {"name": "Parameterized queries (SQLi defense)", "weight": 20, "ok": secure},
        {"name": "CSRF token enforcement", "weight": 15, "ok": secure},
        {"name": "Security headers (CSP, X-Frame-Options…)", "weight": 15, "ok": secure},
        {"name": "Brute-force lockout", "weight": 10, "ok": secure},
        {"name": "Per-IP rate limiting", "weight": 10, "ok": secure},
        {"name": "bcrypt password hashing", "weight": 10, "ok": True},
        {"name": "Tamper-evident audit log", "weight": 10, "ok": chain_ok},
        {"name": "Two-factor auth in use", "weight": 10, "ok": twofa > 0},
    ]
    score = sum(f["weight"] for f in factors if f["ok"])
    grade = ("A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70
             else "D" if score >= 60 else "F")
    return {"score": score, "grade": grade, "factors": factors, "secure": secure}


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
        view=None,
        posture=compute_posture() if session.get("is_admin") else None,
        username=session.get("username"),
        is_admin=session.get("is_admin"),
        recent_events=recent_events,
        secure_mode=is_secure_mode(),
        event_counts=counts,
        max_count=max_count,
        csrf_token=generate_csrf_token(),
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


@bp.route("/admin/mode", methods=["POST"])
@login_required(admin_only=True)
@csrf_protect
def set_mode():
    """Lets an admin flip MODE=secure|vulnerable live from the dashboard —
    the fix for the demo vulnerability is one click, no restart needed."""
    new_mode = request.form.get("mode")
    if new_mode not in ("secure", "vulnerable"):
        abort(400, description="mode must be 'secure' or 'vulnerable'.")
    db = get_db()
    db.execute(
        "INSERT INTO app_state (key, value) VALUES ('mode', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (new_mode,),
    )
    db.commit()
    log_event("mode_changed", detail=new_mode, user_id=session.get("user_id"), ip=request.remote_addr)
    flash(f"Mode switched to {new_mode.upper()}.")
    # Return to the page the toggle was clicked from (e.g. the Attacker view
    # mid-demo), but only for safe same-site relative paths.
    nxt = request.form.get("next") or request.referrer
    if nxt:
        from urllib.parse import urlparse
        p = urlparse(nxt)
        if not p.netloc and p.path.startswith("/"):
            return redirect(p.path + (("?" + p.query) if p.query else ""))
    return redirect(url_for("dashboard.index"))


@bp.route("/admin/flag")
@login_required(admin_only=True)
def flag():
    """Admin-only secret. Used as the capture-the-flag target for the LLM
    pentest agent (validation_suite/llm_agent.py): reaching this page proves
    the agent actually escalated to admin rather than just claiming to."""
    db = get_db()
    row = db.execute("SELECT value FROM secrets WHERE key = 'flag'").fetchone()
    return render_template("flag.html", flag=row["value"], csrf_token=generate_csrf_token())


@bp.route("/view/user")
@login_required()
def user_view():
    """User view: the app as a normal signed-in user experiences it —
    their session, 2FA status, recent account activity."""
    db = get_db()
    uid = session.get("user_id")
    me = db.execute(
        "SELECT username, email, is_admin, totp_enabled, created_at FROM users WHERE id = ?",
        (uid,),
    ).fetchone()
    my_events = db.execute(
        "SELECT event, detail, ip, created_at FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT 10",
        (uid,),
    ).fetchall()
    return render_template(
        "user.html",
        view="user",
        secure_mode=is_secure_mode(),
        me=me,
        my_events=my_events,
    )


@bp.route("/view/defender")
@bp.route("/admin/features")  # kept: old link target
@login_required(admin_only=True)
def features():
    """Defender view: a visual showcase of every security feature, each with
    live data pulled from the running app — one page to demo or screenshot."""
    import json
    from pathlib import Path

    db = get_db()
    secure = is_secure_mode()

    # bcrypt: a real stored hash, with its cost factor
    sample = db.execute(
        "SELECT username, password_hash FROM users WHERE password_hash LIKE '$2%' ORDER BY id LIMIT 1"
    ).fetchone()
    bcrypt_sample = dict(sample) if sample else None
    bcrypt_cost = None
    if bcrypt_sample:
        parts = bcrypt_sample["password_hash"].split("$")
        bcrypt_cost = parts[2] if len(parts) > 3 else None

    # lockout: per-user failed attempts / lock state
    lock_rows = db.execute(
        "SELECT username, failed_attempts, locked_until FROM users ORDER BY failed_attempts DESC LIMIT 5"
    ).fetchall()

    # 2FA: how many users have it, plus a live code for the first one (demo)
    twofa_count = db.execute("SELECT COUNT(*) AS n FROM users WHERE totp_enabled = 1").fetchone()["n"]

    # audit hash-chain: the latest entries + integrity status
    chain_rows = db.execute(
        "SELECT id, event, prev_hash, entry_hash FROM audit_log ORDER BY id DESC LIMIT 6"
    ).fetchall()
    chain_ok, chain_msg = verify_chain()

    # scripted validation suite: last report, if any
    suite = None
    report_path = Path(current_app.root_path).parent / "report" / "validation_report.json"
    try:
        suite = json.loads(report_path.read_text())
    except Exception:
        suite = None

    # AI agent: most recent run summary
    last_run = db.execute("SELECT * FROM agent_runs ORDER BY started_at DESC LIMIT 1").fetchone()

    return render_template(
        "features.html",
        view="defender",
        posture=compute_posture(),
        secure_mode=secure,
        bcrypt_sample=bcrypt_sample,
        bcrypt_cost=bcrypt_cost,
        lock_rows=lock_rows,
        lockout_threshold=3,
        twofa_count=twofa_count,
        chain_rows=list(reversed(chain_rows)),
        chain_ok=chain_ok,
        chain_msg=chain_msg,
        suite=suite,
        last_run=dict(last_run) if last_run else None,
        csrf_token=generate_csrf_token(),
    )


@bp.route("/view/attacker")
@bp.route("/admin/agent")  # kept: old link target
@login_required(admin_only=True)
def attacker_view():
    """Attacker view: pick an attack from the menu and watch the agent run
    it live, with a writeup of how it works and how the app defends."""
    from validation_suite.attack_runner import ATTACKS
    from validation_suite.llm_agent import MAX_STEPS, load_api_keys
    gemini_configured = bool(load_api_keys())
    selected = request.args.get("attack")
    active_run = request.args.get("run_id")

    # Recent runs so the attack history survives navigating away and back.
    recent = get_db().execute(
        "SELECT id, mode_label, attack_id, status, started_at FROM agent_runs "
        "ORDER BY started_at DESC LIMIT 15"
    ).fetchall()
    recent_runs = []
    for r in recent:
        d = dict(r)
        spec = ATTACKS.get(d.get("attack_id"))
        d["title"] = spec["title"] if spec else (d.get("attack_id") or "(earlier run)")
        recent_runs.append(d)

    return render_template(
        "attacker.html",
        view="attacker",
        secure_mode=is_secure_mode(),
        gemini_configured=gemini_configured,
        attacks=ATTACKS,
        selected=selected if selected in ATTACKS else None,
        active_run=active_run,
        recent_runs=recent_runs,
        max_steps=MAX_STEPS,
        csrf_token=generate_csrf_token(),
    )


# Back-compat alias so any old bookmarks to the endpoint name still resolve.
def agent_page():  # pragma: no cover
    return redirect(url_for("dashboard.attacker_view"))


@bp.route("/admin/agent/run", methods=["POST"])
@login_required(admin_only=True)
@csrf_protect
def agent_run():
    from validation_suite.attack_runner import ATTACKS, run_attack
    from validation_suite.llm_agent import AgentStore, DEFAULT_MODEL, load_api_keys
    import uuid

    attack_id = request.form.get("attack", "sqli_login")
    spec = ATTACKS.get(attack_id)
    if spec is None:
        flash("Unknown attack selected.")
        return redirect(url_for("dashboard.attacker_view"))

    api_key = os.environ.get("GEMINI_API_KEY")
    if spec["kind"] == "llm" and not load_api_keys(api_key):
        flash("No Gemini API key available — add keys to api_keys.txt or GEMINI_API_KEY in .env.")
        return redirect(url_for("dashboard.attacker_view", attack=attack_id))

    db_path = Path(current_app.instance_path) / "securegate.db"
    store = AgentStore(db_path)
    base_url = request.host_url.rstrip("/")
    mode_label = "secure" if is_secure_mode() else "vulnerable"
    model = os.environ.get("GEMINI_MODEL", DEFAULT_MODEL)

    # Pre-create the run row synchronously so the redirect target always
    # has a valid run_id to poll, even before the thread's first write.
    run_id = str(uuid.uuid4())
    store.create_run(run_id, mode_label)
    # Record which attack this run was, for the run-history list.
    get_db().execute("UPDATE agent_runs SET attack_id = ? WHERE id = ?", (attack_id, run_id))
    get_db().commit()

    def _worker():
        try:
            run_attack(attack_id, base_url, store, run_id, mode_label, api_key=api_key, model=model)
        except Exception as exc:  # pragma: no cover - defensive
            store.log(run_id, "giveup", f"Worker crashed: {exc!r}")
            store.finish(run_id, "failed", str(exc))

    threading.Thread(target=_worker, daemon=True).start()
    log_event("agent_run_started", detail=f"{attack_id}/{mode_label}",
              user_id=session.get("user_id"), ip=request.remote_addr)
    return redirect(url_for("dashboard.attacker_view", attack=attack_id, run_id=run_id))


@bp.route("/admin/agent/remediate", methods=["POST"])
@login_required(admin_only=True)
@csrf_protect
def agent_remediate():
    """Breach -> fix -> verify: reproduce the attack in vulnerable mode, apply
    the fix (secure mode), and re-run to prove it's blocked. Deterministic,
    no LLM. Restores the original mode when done."""
    from validation_suite.attack_runner import ATTACKS, run_remediation
    from validation_suite.llm_agent import AgentStore
    import uuid

    attack_id = request.form.get("attack", "sqli_login")
    if attack_id not in ATTACKS:
        flash("Unknown attack selected.")
        return redirect(url_for("dashboard.attacker_view"))

    db_path = Path(current_app.instance_path) / "securegate.db"
    store = AgentStore(db_path)
    base_url = request.host_url.rstrip("/")
    run_id = str(uuid.uuid4())
    store.create_run(run_id, "remediation")
    get_db().execute("UPDATE agent_runs SET attack_id = ? WHERE id = ?", (attack_id, run_id))
    get_db().commit()

    def _worker():
        try:
            run_remediation(attack_id, base_url, store, run_id, db_path)
        except Exception as exc:  # pragma: no cover - defensive
            store.log(run_id, "giveup", f"Worker crashed: {exc!r}")
            store.finish(run_id, "failed", str(exc))

    threading.Thread(target=_worker, daemon=True).start()
    log_event("remediation_started", detail=attack_id,
              user_id=session.get("user_id"), ip=request.remote_addr)
    return redirect(url_for("dashboard.attacker_view", attack=attack_id, run_id=run_id))


@bp.route("/admin/agent/status/<run_id>")
@login_required(admin_only=True)
def agent_status(run_id):
    db = get_db()
    run = db.execute("SELECT * FROM agent_runs WHERE id = ?", (run_id,)).fetchone()
    if run is None:
        return jsonify({"error": "unknown run"}), 404
    steps = db.execute(
        "SELECT stage, message, created_at FROM agent_steps WHERE run_id = ? ORDER BY id ASC",
        (run_id,),
    ).fetchall()
    return jsonify({
        "status": run["status"],
        "outcome": run["outcome"],
        "mode_label": run["mode_label"],
        "steps": [dict(s) for s in steps],
    })


# Severity per attack class, for the generated report.
ATTACK_SEVERITY = {
    "sqli_login": "Critical",
    "xss_search": "High",
    "csrf_forged": "High",
    "lockout_bruteforce": "Medium",
    "headers_audit": "Low",
}


@bp.route("/admin/report/<run_id>")
@login_required(admin_only=True)
def report(run_id):
    """A printable pentest report generated from a completed run —
    finding, severity, status, full evidence transcript, and remediation."""
    from validation_suite.attack_runner import ATTACKS
    db = get_db()
    run = db.execute("SELECT * FROM agent_runs WHERE id = ?", (run_id,)).fetchone()
    if run is None:
        abort(404, description="Unknown run.")
    steps = db.execute(
        "SELECT stage, message, created_at FROM agent_steps WHERE run_id = ? ORDER BY id ASC",
        (run_id,),
    ).fetchall()
    attack_id = run["attack_id"]
    spec = ATTACKS.get(attack_id, {})
    status = run["status"]
    # "Open" if the attack succeeded and wasn't remediated; else "Mitigated".
    breached = status in ("captured", "breached")
    finding_state = "OPEN" if breached else ("MITIGATED" if status in ("defended", "remediated") else status.upper())
    return render_template(
        "report.html",
        run=dict(run),
        steps=steps,
        attack_title=spec.get("title", attack_id or "Security test"),
        blurb=spec.get("blurb", ""),
        defense=spec.get("defense", ""),
        severity=ATTACK_SEVERITY.get(attack_id, "Info"),
        finding_state=finding_state,
        breached=breached,
    )
