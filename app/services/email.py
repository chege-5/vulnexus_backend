"""Resend-backed transactional email with safe, reusable templates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from base64 import b64encode
from email.headerregistry import Address
from email.utils import parseaddr
from html import escape
from typing import Any
from urllib.parse import urlencode, urljoin

from email_validator import EmailNotValidError, validate_email

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class EmailContent:
    subject: str
    html: str
    text: str


OPTIONAL_EMAIL_EVENTS = {"scan_completed", "scan_failed", "critical_finding", "report_ready", "subscription", "team_invitation"}
DEFAULT_FROM_NAME = "VulNexus Security Platform"
MAX_REPORT_EMAIL_ATTACHMENT_BYTES = 25 * 1024 * 1024


def _frontend_link(path: str, query: dict[str, str] | None = None) -> str:
    if not settings.FRONTEND_URL:
        raise RuntimeError("FRONTEND_URL is not configured")
    base = settings.FRONTEND_URL.rstrip("/") + "/"
    url = urljoin(base, path.lstrip("/"))
    if query:
        url = f"{url}?{urlencode(query)}"
    return url


def branded_from_value() -> str:
    """Build the single RFC 5322 From value used by every Resend payload."""
    _, legacy_address = parseaddr(settings.EMAIL_FROM or "")
    sender_address = (settings.EMAIL_FROM_ADDRESS or legacy_address).strip()
    sender_name = (settings.EMAIL_FROM_NAME or DEFAULT_FROM_NAME).strip() or DEFAULT_FROM_NAME
    if not sender_address:
        raise RuntimeError("EMAIL_FROM_ADDRESS (or legacy EMAIL_FROM) must be configured")
    try:
        normalized_address = validate_email(sender_address, check_deliverability=False).normalized
    except EmailNotValidError as exc:
        raise ValueError("Invalid configured transactional email sender") from exc
    return str(Address(display_name=sender_name, addr_spec=normalized_address))


def _layout(title: str, body: str, cta_label: str | None = None, cta_url: str | None = None, footer: str = "You received this email because of activity in your VulNexus account.") -> tuple[str, str]:
    safe_title = escape(title)
    safe_footer = escape(footer)
    cta_html = ""
    cta_text = ""
    if cta_label and cta_url:
        cta_html = f'''<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:26px 0 10px"><tr><td align="center" bgcolor="#58c9f5" style="border-radius:8px"><a href="{escape(cta_url, quote=True)}" style="display:inline-block;padding:14px 22px;color:#04121f;font-family:Arial,sans-serif;font-size:14px;font-weight:700;line-height:18px;text-decoration:none">{escape(cta_label)}</a></td></tr></table>'''
        cta_text = f"\n\n{cta_label}: {cta_url}"
    html = f'''<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta http-equiv="x-ua-compatible" content="ie=edge"></head><body style="margin:0;padding:0;background-color:#06111f"><div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">{safe_title} — VulNexus account security.</div><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#06111f" style="width:100%;background-color:#06111f"><tr><td align="center" style="padding:28px 12px"><table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;background-color:#0b1e33;border:1px solid #1c3a57;border-radius:16px;overflow:hidden"><tr><td height="4" bgcolor="#58c9f5" style="height:4px;line-height:4px;font-size:0;background:linear-gradient(90deg,#58c9f5,#45dc9a)">&nbsp;</td></tr><tr><td style="padding:28px 34px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td valign="middle"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td align="center" valign="middle" width="36" height="36" bgcolor="#123756" style="width:36px;height:36px;border:1px solid #2d6b91;border-radius:10px;color:#7de0ff;font-family:Arial,sans-serif;font-size:13px;font-weight:800">VN</td><td style="padding-left:10px"><div style="color:#f6fbff;font-family:Arial,sans-serif;font-size:14px;font-weight:800;letter-spacing:0.8px">VULNEXUS</div><div style="color:#8faabd;font-family:Arial,sans-serif;font-size:11px;letter-spacing:0.7px">SECURITY NOTIFICATION</div></td></tr></table></td><td align="right" valign="middle" style="color:#82dcb0;font-family:Arial,sans-serif;font-size:11px;font-weight:700;letter-spacing:0.7px">PROTECTED</td></tr></table></td></tr><tr><td style="padding:4px 34px 30px"><h1 style="margin:0 0 14px;color:#ffffff;font-family:Arial,sans-serif;font-size:26px;line-height:34px;font-weight:750">{safe_title}</h1><div style="color:#c0d0dd;font-family:Arial,sans-serif;font-size:15px;line-height:24px">{body}</div>{cta_html}<div style="margin-top:26px;padding-top:17px;border-top:1px solid #24435f;color:#829bad;font-family:Arial,sans-serif;font-size:12px;line-height:19px">{safe_footer}</div></td></tr></table><p style="max-width:600px;margin:14px 0 0;color:#658095;font-family:Arial,sans-serif;font-size:11px;line-height:17px;text-align:center">VulNexus security communications · Please do not reply with passwords or verification codes.</p></td></tr></table></body></html>'''
    text = f"VULNEXUS\n\n{title}\n\n{_strip_html(body)}{cta_text}\n\n{footer}"
    return html, text


def _strip_html(value: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", value).replace("&amp;", "&")


def _code_panel(label: str, code: str) -> str:
    return f'''<div style="margin:22px 0;padding:17px 18px;border:1px solid #2d6385;border-radius:12px;background-color:#081a2c;text-align:center"><div style="margin-bottom:8px;color:#8bb9d4;font-family:Arial,sans-serif;font-size:11px;font-weight:700;letter-spacing:1.4px">{escape(label)}</div><div style="color:#ffffff;font-family:Courier New,monospace;font-size:30px;font-weight:700;letter-spacing:8px;line-height:34px">{escape(code)}</div></div>'''


def build_email(event: str, **data: Any) -> EmailContent:
    name = escape(str(data.get("name") or "there"))
    if event == "verification":
        code = str(data["code"])
        url = _frontend_link("/verify-email", {"email": str(data["email"])})
        html, text = _layout("Verify your email", f"<p style=\"margin:0\">Hi {name}, use the code below to securely activate your VulNexus workspace.</p>{_code_panel('YOUR VERIFICATION CODE', code)}<p style=\"margin:0\">This code expires in <strong style=\"color:#ffffff\">24 hours</strong>. Never share it with anyone.</p>", "Enter verification code", url, "You received this because a VulNexus account was created with this email address.")
        return EmailContent("Your VulNexus verification code", html, text)
    if event == "password_reset":
        code = str(data["code"])
        url = _frontend_link("/reset-password/verify", {"email": str(data["email"])})
        html, text = _layout("Reset your password", f"<p style=\"margin:0\">We received a request to reset your VulNexus password.</p>{_code_panel('YOUR RECOVERY CODE', code)}<p style=\"margin:0\">Enter it within <strong style=\"color:#ffffff\">30 minutes</strong>. If you did not make this request, you can safely ignore this email.</p>", "Enter reset code", url, "You received this because a password reset was requested for your VulNexus account.")
        return EmailContent("Your VulNexus password reset code", html, text)
    if event == "password_changed":
        html, text = _layout("Your password was changed", "<p style=\"margin:0 0 12px\">Your VulNexus password was changed successfully.</p><p style=\"margin:0\"><strong style=\"color:#ffffff\">Did not make this change?</strong> Open your security settings immediately and contact your administrator or VulNexus support.</p>", "Review security settings", _frontend_link("/dashboard/settings"), "You received this security notice because your VulNexus password changed.")
        return EmailContent("Your VulNexus password was changed", html, text)
    if event == "welcome":
        html, text = _layout("Welcome to VulNexus", f"<p>Hi {name}, your account is verified and ready.</p><ol><li>Start a security scan.</li><li>Scan a URL, upload code or a ZIP, or connect GitHub.</li><li>Review findings and download a report.</li></ol>", "Start a scan", _frontend_link("/dashboard/scan/new"))
        return EmailContent("Welcome to VulNexus", html, text)
    if event == "admin_announcement":
        raw_title = str(data.get("title") or "VulNexus notification")
        raw_message = str(data.get("message") or "You have a new notification from your administrator.")
        message = escape(raw_message).replace("\n", "<br>")
        path = str(data.get("path") or "/dashboard/notifications")
        html, text = _layout(raw_title, f"<p style=\"margin:0\">{message}</p>", "Open notifications", _frontend_link(path), "You received this message from your VulNexus administrator.")
        return EmailContent(f"VulNexus: {raw_title}", html, raw_message)
    labels = {
        "scan_completed": ("Scan completed", "Your security scan has completed. Review the protected results in VulNexus."),
        "scan_failed": ("Scan needs attention", "A security scan could not be completed. Open VulNexus to review the safe status details and retry if appropriate."),
        "critical_finding": ("Priority finding detected", "A scan identified high-priority security findings. Open VulNexus to review the protected details."),
        "report_ready": ("Report ready", "A security report is ready to review in VulNexus."),
        "team_invitation": ("You have been invited", "You have been invited to collaborate in VulNexus. Open the application to review the invitation."),
        "subscription": ("Subscription update", f"Your VulNexus subscription is now {escape(str(data.get('status') or 'updated'))}."),
    }
    title, message = labels[event]
    path = str(data.get("path") or "/dashboard")
    html, text = _layout(title, f"<p>{message}</p>", "Open VulNexus", _frontend_link(path), "You received this optional product notification because it is enabled in your VulNexus notification preferences.")
    return EmailContent(f"VulNexus: {title}", html, text)


def _send_email_content(
    recipient: str,
    event: str,
    content: EmailContent,
    attachments: list[dict[str, str]] | None = None,
) -> str | None:
    """Send already-rendered content through Resend with the canonical sender."""
    if not settings.EMAIL_ENABLED:
        logger.info("Transactional email skipped event=%s reason=disabled", event)
        return None
    if not settings.RESEND_API_KEY:
        raise RuntimeError("Resend email is enabled but not configured")
    try:
        normalized_recipient = validate_email(recipient, check_deliverability=False).normalized
    except EmailNotValidError as exc:
        raise ValueError("Invalid transactional email recipient") from exc

    import resend

    resend.api_key = settings.RESEND_API_KEY
    resend.default_http_client = resend.RequestsClient(timeout=settings.EMAIL_SEND_TIMEOUT_SECONDS)
    params: dict[str, Any] = {
        "from": branded_from_value(),
        "to": [normalized_recipient],
        "subject": content.subject,
        "html": content.html,
        "text": content.text,
    }
    if settings.EMAIL_REPLY_TO:
        params["reply_to"] = settings.EMAIL_REPLY_TO
    if attachments:
        params["attachments"] = attachments
    response = resend.Emails.send(params)
    message_id = getattr(response, "id", None) or (response.get("id") if isinstance(response, dict) else None)
    logger.info("Transactional email accepted event=%s resend_message_id=%s", event, message_id or "unknown")
    return str(message_id) if message_id else None


def send_transactional_email(recipient: str, event: str, payload: dict[str, Any]) -> str | None:
    """Send a VulNexus transactional event through the centralized Resend path."""
    return _send_email_content(recipient, event, build_email(event, **payload))


def send_report_ready_email(recipient: str, report_path: str, name: str = "") -> str | None:
    """Send the generated report as an attachment through the canonical Resend path."""
    from pathlib import Path

    report = Path(report_path)
    if not report.is_file():
        raise FileNotFoundError("Generated report file is unavailable for email delivery")
    size = report.stat().st_size
    if size > MAX_REPORT_EMAIL_ATTACHMENT_BYTES:
        raise ValueError("Generated report is too large to attach to an email")

    attachment = {
        "filename": f"vulnexus_report_{report.stem}{report.suffix}",
        "content": b64encode(report.read_bytes()).decode("ascii"),
    }
    content = build_email("report_ready", name=name, path="/dashboard/reports")
    return _send_email_content(recipient, "report_ready", content, attachments=[attachment])


def send_sender_identity_test_email(recipient: str) -> tuple[str | None, str]:
    """Send a uniquely identified, non-user-triggered sender branding check."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    content = EmailContent(
        subject=f"VulNexus sender identity check {timestamp}",
        html="<p>This is a VulNexus sender-identity test. No action is required.</p>",
        text="This is a VulNexus sender-identity test. No action is required.",
    )
    return _send_email_content(recipient, "sender_identity_test", content), branded_from_value()


def queue_transactional_email(recipient: str, event: str, payload: dict[str, Any]) -> bool:
    """Deliver after the caller's database transaction has committed.

    Failures are contained so a Resend outage never rolls back authentication,
    subscription, report, or scan state.
    """
    if not settings.EMAIL_ENABLED:
        return False
    try:
        send_transactional_email(recipient, event, payload)
        return True
    except Exception:
        logger.exception("Transactional email delivery failed event=%s", event)
        return False


def queue_report_ready_email(recipient: str, report_path: str, name: str = "") -> bool:
    """Attach a generated report without allowing delivery failures to affect the download."""
    if not settings.EMAIL_ENABLED:
        return False
    try:
        send_report_ready_email(recipient, report_path, name)
        return True
    except Exception:
        logger.exception("Transactional report email delivery failed")
        return False


def notification_email_enabled(preferences: dict | None, event: str) -> bool:
    defaults = {"scan_completed": True, "scan_failed": True, "report_ready": True, "subscription": True, "critical_finding": False, "team_invitation": True}
    return bool((preferences or {}).get(event, defaults.get(event, False)))


async def send_email_verification(recipient: str, code: str, name: str = "") -> bool:
    return queue_transactional_email(recipient, "verification", {"code": code, "name": name, "email": recipient})


async def send_password_reset_email(recipient: str, code: str, name: str = "") -> bool:
    return queue_transactional_email(recipient, "password_reset", {"code": code, "name": name, "email": recipient})
