"""Minimal transactional-email delivery for security-sensitive account flows."""

from __future__ import annotations

import asyncio
import smtplib
from email.message import EmailMessage
from urllib.parse import urlencode

from app.config import settings


def _send_password_reset_email(recipient: str, token: str) -> None:
    if not settings.SMTP_HOST or not settings.SMTP_FROM_EMAIL or not settings.PASSWORD_RESET_URL:
        raise RuntimeError("Password reset email is not configured")

    separator = "&" if "?" in settings.PASSWORD_RESET_URL else "?"
    reset_url = f"{settings.PASSWORD_RESET_URL}{separator}{urlencode({'token': token})}"
    message = EmailMessage()
    message["Subject"] = "Reset your VulNexus password"
    message["From"] = settings.SMTP_FROM_EMAIL
    message["To"] = recipient
    message.set_content(
        f"Use this link to reset your password. It expires in 30 minutes:\n\n{reset_url}\n\n"
        "If you did not request this, you can ignore this email."
    )

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as client:
        client.starttls()
        if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
            client.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        client.send_message(message)


async def send_password_reset_email(recipient: str, token: str) -> None:
    await asyncio.to_thread(_send_password_reset_email, recipient, token)
