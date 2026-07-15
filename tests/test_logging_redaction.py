import logging

from app.utils.logger import SecretRedactionFilter, configure_log_redaction
from app.services.report_generator import generate_html_report
from app.utils.redaction import redact_data, redact_headers, redact_log_message, redact_url


def test_redact_url_masks_sensitive_values_and_preserves_safe_query_parameters():
    assert redact_url("https://api.shodan.io/shodan/host/1.1.1.1?key=abc123") == "https://api.shodan.io/shodan/host/1.1.1.1?key=[REDACTED]"
    assert redact_url("https://api.builtwith.com/free1/api.json?KEY=abc123&LOOKUP=example.com") == "https://api.builtwith.com/free1/api.json?KEY=[REDACTED]&LOOKUP=example.com"
    assert redact_url("https://api.example.com/lookup?domain=example.com&token=top-secret") == "https://api.example.com/lookup?domain=example.com&token=[REDACTED]"


def test_redact_headers_and_database_urls():
    assert redact_headers({"Authorization": "Bearer abc123", "Accept": "application/json"}) == {"Authorization": "Bearer [REDACTED]", "Accept": "application/json"}
    safe = redact_data({"DATABASE_URL": "postgresql://vulnexus:password123@db.local/vulnexus"})
    assert "password123" not in safe["DATABASE_URL"]
    assert safe["DATABASE_URL"] == "postgresql://[REDACTED]@db.local/vulnexus"


def test_provider_secrets_never_survive_free_text_redaction():
    message = "CENSYS_PAT=censys-live-secret NVIDIA_API_KEY=nvidia-live-secret OPENROUTER_API_KEY=router-live-secret GITHUB_TOKEN=github-live-secret"
    safe = redact_log_message(message)
    for secret in ("censys-live-secret", "nvidia-live-secret", "router-live-secret", "github-live-secret"):
        assert secret not in safe


def test_httpx_logger_filter_sanitizes_request_messages(caplog):
    configure_log_redaction()
    caplog.set_level(logging.INFO, logger="httpx")
    logging.getLogger("httpx").info(
        'HTTP Request: GET https://api.shodan.io/shodan/host/1.1.1.1?key=shodan-live-secret "HTTP/2 403 Forbidden"'
    )
    assert "shodan-live-secret" not in caplog.text
    assert "key=[REDACTED]" in caplog.text


def test_filter_sanitizes_authorization_arguments_and_exception_text():
    record = logging.LogRecord(
        "httpx", logging.ERROR, __file__, 1, "Authorization: Bearer %s", ("token-that-must-not-appear",), None
    )
    SecretRedactionFilter().filter(record)
    assert "token-that-must-not-appear" not in record.getMessage()
    assert record.getMessage() == "Authorization: Bearer [REDACTED]"


def test_generated_html_report_never_contains_provider_credentials():
    secret = "report-only-provider-secret"
    report = generate_html_report(
        scan_id="scan-1",
        target=f"https://example.com/?token={secret}",
        scan_type="url",
        overall_score=10,
        vulnerabilities=[{"description": f"OPENROUTER_API_KEY={secret}", "severity": "Low"}],
        cve_details=[{"request_headers": {"X-Api-Key": secret}}],
    )
    assert secret not in report
    assert "[REDACTED]" in report
