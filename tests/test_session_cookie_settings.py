from __future__ import annotations

from app.config import Settings


def _production_environment(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://user:pass@db.example/vulnexus")
    monkeypatch.setenv("ASYNC_DATABASE_URL", "postgresql+asyncpg://user:pass@db.example/vulnexus")
    monkeypatch.setenv("SECRET_KEY", "s" * 48)
    monkeypatch.setenv("JWT_SECRET", "j" * 48)
    monkeypatch.setenv("SESSION_SECRET", "r" * 48)
    monkeypatch.setenv("OAUTH_STATE_SECRET", "o" * 48)
    monkeypatch.setenv("CSRF_SECRET", "c" * 48)
    monkeypatch.setenv("METRICS_TOKEN", "m" * 48)
    monkeypatch.setenv("SMTP_HOST", "smtp.example")
    monkeypatch.setenv("SMTP_FROM_EMAIL", "security@example.com")
    monkeypatch.setenv("PASSWORD_RESET_URL", "https://app.example/reset-password")
    monkeypatch.setenv("EMAIL_VERIFICATION_URL", "https://app.example/verify-email")
    monkeypatch.setenv("CORS_ORIGINS", "https://app.example")
    monkeypatch.setenv("FRONTEND_URL", "https://app.example")
    monkeypatch.setenv("BACKEND_URL", "https://api.example")
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "https://api.example/api/v1/auth/google/callback")
    monkeypatch.setenv("GITHUB_REDIRECT_URI", "https://api.example/api/v1/auth/github/callback")
    monkeypatch.setenv("EMAIL_ENABLED", "false")


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


def test_production_refuses_missing_oauth_state_secret(monkeypatch) -> None:
    _production_environment(monkeypatch)
    monkeypatch.delenv("OAUTH_STATE_SECRET", raising=False)

    try:
        Settings()
    except RuntimeError as exc:
        assert "OAUTH_STATE_SECRET" in str(exc)
    else:
        raise AssertionError("production accepted a missing OAuth state secret")


def test_production_refuses_missing_provider_redirect_uri(monkeypatch) -> None:
    _production_environment(monkeypatch)
    monkeypatch.delenv("GOOGLE_REDIRECT_URI", raising=False)

    try:
        Settings()
    except RuntimeError as exc:
        assert "GOOGLE_REDIRECT_URI" in str(exc)
    else:
        raise AssertionError("production accepted a missing Google redirect URI")


def test_production_refuses_frontend_as_provider_callback(monkeypatch) -> None:
    _production_environment(monkeypatch)
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "https://app.example/api/v1/auth/google/callback")

    try:
        Settings()
    except RuntimeError as exc:
        assert "must not use the FRONTEND_URL hostname" in str(exc)
    else:
        raise AssertionError("production accepted a frontend OAuth callback")


def test_production_requires_independent_session_and_jwt_secrets(monkeypatch) -> None:
    _production_environment(monkeypatch)
    monkeypatch.delenv("JWT_SECRET", raising=False)

    try:
        Settings()
    except RuntimeError as exc:
        assert "JWT_SECRET" in str(exc)
    else:
        raise AssertionError("production accepted SECRET_KEY as a JWT_SECRET alias")
