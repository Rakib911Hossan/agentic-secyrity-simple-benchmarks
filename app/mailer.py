"""Email sending for OTP-less alerts, password recovery links, and new-device
notices. Falls back to printing the email to the console/log when SMTP isn't
configured, so the demo works offline."""
import smtplib
import ssl
from email.message import EmailMessage
from flask import current_app


def send_email(to_addr: str, subject: str, body: str):
    cfg = current_app.config
    host = cfg.get("SMTP_HOST")
    user = cfg.get("SMTP_USER")
    password = cfg.get("SMTP_PASSWORD")

    if not host or not user or not password:
        current_app.logger.info(
            "[mailer:fallback] To=%s Subject=%s\n%s", to_addr, subject, body
        )
        return

    msg = EmailMessage()
    msg["From"] = user
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL(host, cfg.get("SMTP_PORT", 465), context=context) as server:
            server.login(user, password)
            server.send_message(msg)
    except Exception as exc:  # pragma: no cover - network dependent
        current_app.logger.warning("Email send failed (%s); falling back to log.", exc)
        current_app.logger.info(
            "[mailer:fallback] To=%s Subject=%s\n%s", to_addr, subject, body
        )


def send_new_device_alert(to_addr: str, username: str, ip: str):
    send_email(
        to_addr,
        "SecureGate: new device login",
        f"Hi {username},\n\nYour account was just accessed from a new device/IP ({ip}).\n"
        "If this wasn't you, reset your password immediately.",
    )


def send_password_reset(to_addr: str, username: str, reset_link: str):
    send_email(
        to_addr,
        "SecureGate: password reset requested",
        f"Hi {username},\n\nUse this link to reset your password (expires in 15 minutes):\n{reset_link}",
    )
