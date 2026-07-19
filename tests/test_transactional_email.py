from __future__ import annotations

import sys
from types import SimpleNamespace

from app.services import email


def test_templates_escape_dynamic_values_and_keep_codes_out_of_subjects(monkeypatch) -> None:
    monkeypatch.setattr(email.settings, "FRONTEND_URL", "https://app.example.com")
    code = "123456"
    content = email.build_email("verification", name="<script>alert(1)</script>", email="person@example.com", code=code)

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content.html
    assert code not in content.subject
    assert code in content.text
    assert "verify-email?email=person%40example.com" in content.text


def test_disabled_email_does_not_queue_or_crash(monkeypatch) -> None:
    monkeypatch.setattr(email.settings, "EMAIL_ENABLED", False)
    assert email.queue_transactional_email("person@example.com", "welcome", {"name": "Person"}) is False


def test_notification_preferences_default_to_opt_in_for_critical_alerts() -> None:
    assert email.notification_email_enabled({}, "scan_completed") is True
    assert email.notification_email_enabled({}, "critical_finding") is False
    assert email.notification_email_enabled({"critical_finding": True}, "critical_finding") is True


def test_admin_announcement_template_preserves_text_and_escapes_html() -> None:
    content = email.build_email("admin_announcement", title="Service <notice>", message="Line one\nLine two", path="/dashboard/notifications")
    assert content.subject == "VulNexus: Service <notice>"
    assert "Service &lt;notice&gt;" in content.html
    assert "Line one<br>Line two" in content.html
    assert content.text == "Line one\nLine two"


def test_every_resend_event_uses_the_exact_branded_from_value(monkeypatch) -> None:
    sent: list[dict] = []

    class FakeRequestsClient:
        def __init__(self, timeout: int) -> None:
            self.timeout = timeout

    class FakeEmails:
        @staticmethod
        def send(payload: dict) -> dict:
            sent.append(payload)
            return {"id": f"message-{len(sent)}"}

    fake_resend = SimpleNamespace(RequestsClient=FakeRequestsClient, Emails=FakeEmails)
    monkeypatch.setitem(sys.modules, "resend", fake_resend)
    monkeypatch.setattr(email.settings, "EMAIL_ENABLED", True)
    monkeypatch.setattr(email.settings, "RESEND_API_KEY", "test-key")
    monkeypatch.setattr(email.settings, "EMAIL_FROM_NAME", "VulNexus Security Platform")
    monkeypatch.setattr(email.settings, "EMAIL_FROM_ADDRESS", "security@jimmysite.me")
    monkeypatch.setattr(email.settings, "EMAIL_FROM", None)
    monkeypatch.setattr(email.settings, "EMAIL_REPLY_TO", "support@jimmysite.me")
    monkeypatch.setattr(email.settings, "FRONTEND_URL", "https://app.example.com")

    event_payloads = {
        "verification": {"name": "Person", "email": "person@example.com", "code": "123456"},
        "password_reset": {"name": "Person", "email": "person@example.com", "code": "123456"},
        "password_changed": {"name": "Person"},
        "welcome": {"name": "Person"},
        "scan_completed": {"name": "Person", "path": "/dashboard/scans/1"},
        "scan_failed": {"name": "Person", "path": "/dashboard/scans/1"},
        "critical_finding": {"name": "Person", "path": "/dashboard/scans/1"},
        "report_ready": {"name": "Person", "path": "/dashboard/reports"},
        "team_invitation": {"name": "Person", "path": "/dashboard/team"},
        "subscription": {"name": "Person", "path": "/dashboard/billing", "status": "active"},
    }

    for event, payload in event_payloads.items():
        email.send_transactional_email("person@example.com", event, payload)

    expected_from = "VulNexus Security Platform <security@jimmysite.me>"
    assert len(sent) == len(event_payloads)
    assert {payload["from"] for payload in sent} == {expected_from}
    assert {payload.get("reply_to") for payload in sent} == {"support@jimmysite.me"}


def test_branded_from_uses_the_display_name_with_a_legacy_combined_sender(monkeypatch) -> None:
    monkeypatch.setattr(email.settings, "EMAIL_FROM_NAME", "VulNexus Security Platform")
    monkeypatch.setattr(email.settings, "EMAIL_FROM_ADDRESS", None)
    monkeypatch.setattr(email.settings, "EMAIL_FROM", "Old Name <security@jimmysite.me>")

    assert email.branded_from_value() == "VulNexus Security Platform <security@jimmysite.me>"
