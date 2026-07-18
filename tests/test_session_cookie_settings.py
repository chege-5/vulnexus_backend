from __future__ import annotations

from app.config import Settings


def _production_environment(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://user:pass@db.example/vulnexus")
    monkeypatch.setenv("ASYNC_DATABASE_URL", "postgresql+asyncpg://user:pass@db.example/vulnexus")
    monkeypatch.setenv("SECRET_KEY", "s" * 48)
    monkeypatch.setenv("CSRF_SECRET", "c" * 48)
    monkeypatch.setenv("METRICS_TOKEN", "m" * 48)
    monkeypatch.setenv("SMTP_HOST", "smtp.example")
    monkeypatch.setenv("SMTP_FROM_EMAIL", "security@example.com")
    monkeypatch.setenv("PASSWORD_RESET_URL", "https://app.example/reset-password")
    monkeypatch.setenv("EMAIL_VERIFICATION_URL", "https://app.example/verify-email")
    monkeypatch.setenv("CORS_ORIGINS", "https://app.example")


def test_production_cross_site_refresh_cookie_defaults_to_none_and_secure(monkeypatch) -> None:
    _production_environment(monkeypatch)
    monkeypatch.delenv("SESSION_COOKIE_SAMESITE", raising=False)
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)

    settings = Settings()

    assert settings.SESSION_COOKIE_SAMESITE == "none"
    assert settings.SESSION_COOKIE_SECURE is True


def test_cross_site_refresh_cookie_cannot_be_insecure(monkeypatch) -> None:
    _production_environment(monkeypatch)
    monkeypatch.setenv("SESSION_COOKIE_SAMESITE", "none")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")

    try:
        Settings()
    except RuntimeError as exc:
        assert "SESSION_COOKIE_SECURE" in str(exc)
    else:
        raise AssertionError("insecure cross-site refresh cookie configuration was accepted")
