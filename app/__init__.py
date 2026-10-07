"""Application factory. MODE=secure|vulnerable controls whether the demo
weaknesses (string-built SQL, no CSRF check, no escaping, no lockout) are
active. Vulnerable mode exists only to give the validation suite something
real to catch and must never be used outside a local demo."""
import os
from datetime import timedelta
from pathlib import Path

from flask import Flask
from cryptography.fernet import Fernet
from dotenv import load_dotenv

from app.db import register_db, init_db
from app.security import apply_security_headers

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


def create_app():
    app = Flask(__name__, instance_relative_config=True, instance_path=str(BASE_DIR / "instance"))

    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-change-me"),
        FERNET_KEY=os.environ.get("FERNET_KEY") or Fernet.generate_key().decode(),
        MODE=os.environ.get("MODE", "secure"),
        SMTP_HOST=os.environ.get("SMTP_HOST"),
        SMTP_PORT=int(os.environ.get("SMTP_PORT", 465)),
        SMTP_USER=os.environ.get("SMTP_USER"),
        SMTP_PASSWORD=os.environ.get("SMTP_PASSWORD"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    )

    if app.config["MODE"] == "vulnerable" and not app.debug:
        app.logger.warning(
            "SecureGate is running in VULNERABLE demo mode — do not expose this outside localhost."
        )

    register_db(app)
    init_db(app)

    from app.auth import bp as auth_bp
    from app.dashboard import bp as dashboard_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    app.after_request(apply_security_headers)

    @app.route("/")
    def root():
        from flask import redirect, url_for, session
        if "user_id" in session:
            return redirect(url_for("dashboard.index"))
        return redirect(url_for("auth.login"))

    @app.cli.command("seed-admin")
    def seed_admin():
        """flask --app app seed-admin — creates an initial admin user."""
        import bcrypt
        from app.db import get_db
        with app.app_context():
            db = get_db()
            password_hash = bcrypt.hashpw(b"ChangeMe!123", bcrypt.gensalt()).decode()
            db.execute(
                "INSERT OR IGNORE INTO users (username, email, password_hash, is_admin) "
                "VALUES (?, ?, ?, 1)",
                ("admin", "admin@example.com", password_hash),
            )
            db.commit()
            print("Seeded admin / ChangeMe!123 — change this password immediately.")

    return app
