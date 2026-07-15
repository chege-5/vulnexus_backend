"""Transactional-email delivery for security-sensitive account flows."""

from __future__ import annotations

import asyncio
import logging
import smtplib
from email.message import EmailMessage
from urllib.parse import urlencode

from app.config import settings

logger = logging.getLogger(__name__)


def _link(base_url: str, token: str) -> str:
    separator = "&" if "?" in base_url else "?"
    return f"{base_url}{separator}{urlencode({'token': token})}"


def _deliver_message(message: EmailMessage) -> None:
    if not settings.SMTP_HOST or not settings.SMTP_FROM_EMAIL:
        if settings.IS_PRODUCTION:
            raise RuntimeError("SMTP is not configured")
        logger.warning("Development email delivery skipped: subject=%s to=%s", message["Subject"], message["To"])
        logger.warning("Development email body:\n%s", message.get_content())
        return

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as client:
        client.starttls()
        if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
            client.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        client.send_message(message)


def _build_email(recipient: str, subject: str, body: str) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.SMTP_FROM_EMAIL or "dev@vulnexus.local"
    message["To"] = recipient
    message.set_content(body)
    return message


def _send_password_reset_email(recipient: str, token: str) -> None:
    if not settings.PASSWORD_RESET_URL:
        raise RuntimeError("Password reset URL is not configured")
    reset_url = _link(settings.PASSWORD_RESET_URL, token)
    _deliver_message(_build_email(
        recipient,
        "Reset your VulNexus password",
        (
            "Use this link to reset your VulNexus password. It expires in 30 minutes:\n\n"
            f"{reset_url}\n\n"
            "If you did not request this, you can ignore this email."
        ),
    ))


def _send_email_verification(recipient: str, token: str) -> None:
    if not settings.EMAIL_VERIFICATION_URL:
        raise RuntimeError("Email verification URL is not configured")
    verification_url = _link(settings.EMAIL_VERIFICATION_URL, token)
    _deliver_message(_build_email(
        recipient,
        "Verify your VulNexus account",
        (
            "Confirm this email address for your VulNexus account. The link expires in 24 hours:\n\n"
            f"{verification_url}\n\n"
            "If you did not create this account, you can ignore this email."
        ),
    ))


async def send_password_reset_email(recipient: str, token: str) -> None:
    await asyncio.to_thread(_send_password_reset_email, recipient, token)


async def send_email_verification(recipient: str, token: str) -> None:
    await asyncio.to_thread(_send_email_verification, recipient, token)
