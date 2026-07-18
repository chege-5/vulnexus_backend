from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
BASE_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BASE_DIR / ".env")


def _get_str(name: str, default: str) -> str:
    return os.getenv(name, default)


def _get_first_str(names: tuple[str, ...], default: str) -> str:
    for name in names:
        value = os.getenv(name)
        if value is not None and value.strip() != "":
            return value
    return default


def _get_optional_str(name: str) -> Optional[str]:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return None
    return value


def _get_first_optional_str(names: tuple[str, ...]) -> Optional[str]:
    for name in names:
        value = _get_optional_str(name)
        if value is not None:
            return value
    return None


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return float(value)
    except ValueError:
        return default


class Settings:
    def __init__(self) -> None:
        self.ENVIRONMENT = _get_str("ENVIRONMENT", "development").strip().lower()
        self.IS_PRODUCTION = self.ENVIRONMENT in {"production", "prod"}
        self.DATABASE_URL = _get_str("DATABASE_URL", "postgresql+asyncpg://vulnexus:vulnexus@localhost:5432/vulnexusdb")
        self.DATABASE_URL = self._normalize_database_url(self.DATABASE_URL)
        self.ASYNC_DATABASE_URL = _get_str("ASYNC_DATABASE_URL", self.DATABASE_URL)
        self.ASYNC_DATABASE_URL = self._normalize_database_url(self.ASYNC_DATABASE_URL)
        if self.ASYNC_DATABASE_URL != self.DATABASE_URL:
            raise RuntimeError(
                "ASYNC_DATABASE_URL is deprecated and must match DATABASE_URL; "
                "FastAPI and Alembic use DATABASE_URL as the single source of truth"
            )
        self.REDIS_URL = _get_str("REDIS_URL", "redis://localhost:6379/0")
        self.CELERY_BROKER_URL = _get_str("CELERY_BROKER_URL", self.REDIS_URL)
        self.CELERY_RESULT_BACKEND = _get_str("CELERY_RESULT_BACKEND", self.REDIS_URL)
        self.CELERY_WORKER_PREFETCH_MULTIPLIER = _get_int("CELERY_WORKER_PREFETCH_MULTIPLIER", 1)
        self.CELERY_TASK_SOFT_TIME_LIMIT = _get_int("CELERY_TASK_SOFT_TIME_LIMIT", 180)
        self.CELERY_TASK_TIME_LIMIT = max(
            self.CELERY_TASK_SOFT_TIME_LIMIT + 1,
            _get_int("CELERY_TASK_TIME_LIMIT", 210),
        )
        self.VULNEXUS_CELERY_WORKER = _get_bool("VULNEXUS_CELERY_WORKER", False)
        self.SECRET_KEY = _get_optional_str("SECRET_KEY")
        self.ALGORITHM = _get_str("ALGORITHM", "HS256")

        self.ACCESS_TOKEN_EXPIRE_MINUTES = _get_int("ACCESS_TOKEN_EXPIRE_MINUTES", 60)
        self.REFRESH_TOKEN_EXPIRE_DAYS = _get_int("REFRESH_TOKEN_EXPIRE_DAYS", 30)
        self.CORS_ORIGINS = _get_str("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")

        self.UPLOAD_DIR = _get_str("UPLOAD_DIR", "./uploads")
        self.MAX_UPLOAD_SIZE_MB = _get_int("MAX_UPLOAD_SIZE_MB", 50)
        self.MAX_ZIP_ENTRIES = _get_int("MAX_ZIP_ENTRIES", 500)
        self.MAX_ZIP_UNCOMPRESSED_MB = _get_int("MAX_ZIP_UNCOMPRESSED_MB", 200)
        self.MAX_ZIP_RATIO = _get_int("MAX_ZIP_RATIO", 100)
        self.VERIFY_SCAN_TARGETS = _get_bool("VERIFY_SCAN_TARGETS", True)
        self.SCAN_TIMEOUT = _get_int("SCAN_TIMEOUT", 60)
        self.DNS_RESOLUTION_TIMEOUT_SECONDS = _get_float("DNS_RESOLUTION_TIMEOUT_SECONDS", 5.0)
        self.ENABLE_LIVE_INTELLIGENCE = _get_bool("ENABLE_LIVE_INTELLIGENCE", True)
        self.ENABLE_AI_ENRICHMENT = _get_bool("ENABLE_AI_ENRICHMENT", True)
        self.ENABLE_AI_DURING_SCAN = _get_bool("ENABLE_AI_DURING_SCAN", False)
        self.ENABLE_REPORT_GENERATION_DURING_SCAN = _get_bool("ENABLE_REPORT_GENERATION_DURING_SCAN", True)
        self.TLS_CONNECT_TIMEOUT_SECONDS = _get_float("TLS_CONNECT_TIMEOUT_SECONDS", 6.0)
        self.TLS_NEAR_EXPIRY_DAYS = _get_int("TLS_NEAR_EXPIRY_DAYS", 30)
        self.TLS_MIN_VERSION = _get_str("TLS_MIN_VERSION", "TLSv1.2")
        self.TLS_REQUIRE_VERSION = _get_str("TLS_REQUIRE_VERSION", "TLSv1.3")
        self.TLS_REQUIRE_FORWARD_SECRECY = _get_bool("TLS_REQUIRE_FORWARD_SECRECY", True)
        self.TLS_HSTS_MIN_AGE_SECONDS = _get_int("TLS_HSTS_MIN_AGE_SECONDS", 31536000)
        self.TLS_MIN_RSA_BITS = _get_int("TLS_MIN_RSA_BITS", 2048)
        self.TLS_MIN_EC_BITS = _get_int("TLS_MIN_EC_BITS", 224)
        self.SOURCE_CONTEXT_LINES = _get_int("SOURCE_CONTEXT_LINES", 2)
        self.MAX_CONCURRENT_SCANS = _get_int("MAX_CONCURRENT_SCANS", 10)
        self.ENABLE_PARALLEL_SCANNERS = _get_bool("ENABLE_PARALLEL_SCANNERS", True)
        self.ENABLE_PROVIDER_HEALTHCHECKS = _get_bool("ENABLE_PROVIDER_HEALTHCHECKS", True)
        self.ENABLE_SCAN_CACHE = _get_bool("ENABLE_SCAN_CACHE", True)
        self.ENABLE_RESULT_CACHE = _get_bool("ENABLE_RESULT_CACHE", True)
        self.ENABLE_SCAN_LOGGING = _get_bool("ENABLE_SCAN_LOGGING", True)
        self.ENABLE_RATE_LIMITING = _get_bool("ENABLE_RATE_LIMITING", True)
        self.ENABLE_INTELLIGENCE_CORRELATION = _get_bool("ENABLE_INTELLIGENCE_CORRELATION", True)
        self.ENABLE_ASYNC_LOOKUPS = _get_bool("ENABLE_ASYNC_LOOKUPS", True)
        self.MAX_PARALLEL_LOOKUPS = _get_int("MAX_PARALLEL_LOOKUPS", 8)
        self.MAX_PARALLEL_SCANNERS = _get_int("MAX_PARALLEL_SCANNERS", 6)
        self.ENABLE_TLS_SCAN = _get_bool("ENABLE_TLS_SCAN", True)
        self.ENABLE_HEADER_SCAN = _get_bool("ENABLE_HEADER_SCAN", True)
        self.ENABLE_DNS_SCAN = _get_bool("ENABLE_DNS_SCAN", True)
        self.ENABLE_SUBDOMAIN_SCAN = _get_bool("ENABLE_SUBDOMAIN_SCAN", True)
        self.ENABLE_PORT_SCAN = _get_bool("ENABLE_PORT_SCAN", True)
        self.ENABLE_TECH_STACK_SCAN = _get_bool("ENABLE_TECH_STACK_SCAN", True)
        self.ENABLE_REPUTATION_SCAN = _get_bool("ENABLE_REPUTATION_SCAN", True)
        self.ENABLE_THREAT_INTELLIGENCE = _get_bool("ENABLE_THREAT_INTELLIGENCE", True)
        self.ENABLE_CVE_MAPPING = _get_bool("ENABLE_CVE_MAPPING", True)
        self.ENABLE_CWE_MAPPING = _get_bool("ENABLE_CWE_MAPPING", True)
        self.ENABLE_EPSS_SCORING = _get_bool("ENABLE_EPSS_SCORING", True)
        self.ENABLE_CISA_KEV_CHECK = _get_bool("ENABLE_CISA_KEV_CHECK", True)
        self.ENABLE_AI_SCORING = _get_bool("ENABLE_AI_SCORING", True)
        self.ENABLE_REPORT_GENERATION = _get_bool("ENABLE_REPORT_GENERATION", True)

        self.NVD_API_KEY = _get_optional_str("NVD_API_KEY")
        self.NVD_API_URL = _get_str("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.CISA_KEV_URL = _get_str("CISA_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        self.EPSS_API_URL = _get_str("EPSS_API_URL", "https://api.first.org/data/v1/epss")
        self.SSL_LABS_API_URL = _get_str("SSL_LABS_API_URL", "https://api.ssllabs.com/api/v3")
        self.CVE_CIRCL_API_URL = _get_str("CVE_CIRCL_API_URL", "https://cve.circl.lu/api")
        self.MITRE_CVE_API_URL = _get_str("MITRE_CVE_API_URL", "https://cveawg.mitre.org/api")
        self.OSV_API_URL = _get_str("OSV_API_URL", "https://api.osv.dev/v1")
        self.GITHUB_ADVISORY_API_URL = _get_str("GITHUB_ADVISORY_API_URL", "https://api.github.com/advisories")

        self.SHODAN_API_KEY = _get_optional_str("SHODAN_API_KEY")
        self.SHODAN_ENABLED = _get_bool("ENABLE_SHODAN", _get_bool("SHODAN_ENABLED", False))
        self.SHODAN_API_URL = _get_str("SHODAN_API_URL", "https://api.shodan.io")
        self.SHODAN_PLAN = _get_str("SHODAN_PLAN", "free").strip().lower()
        self.SHODAN_TIMEOUT_SECONDS = _get_int("SHODAN_TIMEOUT_SECONDS", 10)
        self.SHODAN_ENABLE_HOST_LOOKUP = _get_bool("SHODAN_ENABLE_HOST_LOOKUP", True)
        # These controls are deliberately default-deny. The VulNexus adapter does
        # not implement Enterprise-only Shodan APIs or on-demand scanning.
        self.SHODAN_ENABLE_SEARCH = _get_bool("SHODAN_ENABLE_SEARCH", False)
        self.SHODAN_ENABLE_ON_DEMAND_SCAN = _get_bool("SHODAN_ENABLE_ON_DEMAND_SCAN", False)
        self.SHODAN_ENABLE_STREAMING = _get_bool("SHODAN_ENABLE_STREAMING", False)
        self.SHODAN_ENABLE_BULK_DATA = _get_bool("SHODAN_ENABLE_BULK_DATA", False)
        self.CENSYS_ENABLED = _get_bool("ENABLE_CENSYS", _get_bool("CENSYS_ENABLED", False))
        self.CENSYS_API_BASE_URL = _get_str("CENSYS_API_BASE_URL", "https://api.platform.censys.io/v3/global")
        self.CENSYS_PAT = _get_optional_str("CENSYS_PAT")
        self.CENSYS_ORGANIZATION_ID = _get_optional_str("CENSYS_ORGANIZATION_ID")
        self.CENSYS_TIMEOUT_SECONDS = _get_int("CENSYS_TIMEOUT_SECONDS", 15)
        self.SECURITYTRAILS_API_KEY = _get_optional_str("SECURITYTRAILS_API_KEY")
        self.SECURITYTRAILS_API_URL = _get_str("SECURITYTRAILS_API_URL", "https://api.securitytrails.com/v1")
        self.SECURITYTRAILS_ENABLED = _get_bool("SECURITYTRAILS_ENABLED", False)
        self.VIRUSTOTAL_API_KEY = _get_optional_str("VIRUSTOTAL_API_KEY")
        self.VIRUSTOTAL_ENABLED = _get_bool("ENABLE_VIRUSTOTAL", _get_bool("VIRUSTOTAL_ENABLED", False))
        self.VIRUSTOTAL_API_URL = _get_first_str(("VIRUSTOTAL_BASE_URL", "VIRUSTOTAL_API_URL"), "https://www.virustotal.com/api/v3")
        self.VIRUSTOTAL_TIMEOUT_SECONDS = _get_int("VIRUSTOTAL_TIMEOUT_SECONDS", 15)
        self.VIRUSTOTAL_ALLOW_FILE_UPLOAD = _get_bool("VIRUSTOTAL_ALLOW_FILE_UPLOAD", False)
        self.ABUSEIPDB_API_KEY = _get_optional_str("ABUSEIPDB_API_KEY")
        self.ABUSEIPDB_API_URL = _get_str("ABUSEIPDB_API_URL", "https://api.abuseipdb.com/api/v2")
        self.ABUSEIPDB_ENABLED = _get_bool("ABUSEIPDB_ENABLED", False)
        self.GOOGLE_SAFE_BROWSING_API_KEY = _get_optional_str("GOOGLE_SAFE_BROWSING_API_KEY")
        self.GOOGLE_SAFE_BROWSING_API_URL = _get_str("GOOGLE_SAFE_BROWSING_API_URL", "https://safebrowsing.googleapis.com/v4")
        self.GOOGLE_SAFE_BROWSING_ENABLED = _get_bool("GOOGLE_SAFE_BROWSING_ENABLED", False)
        self.IPINFO_API_KEY = _get_optional_str("IPINFO_API_KEY")
        self.IPINFO_API_URL = _get_str("IPINFO_API_URL", "https://ipinfo.io")
        self.IPINFO_ENABLED = _get_bool("IPINFO_ENABLED", False)
        self.BUILTWITH_API_KEY = _get_optional_str("BUILTWITH_API_KEY")
        self.BUILTWITH_API_URL = _get_str("BUILTWITH_API_URL", "https://api.builtwith.com")
        self.BUILTWITH_ENABLED = _get_bool("BUILTWITH_ENABLED", False)
        self.BUILTWITH_CACHE_TTL_SECONDS = _get_int("BUILTWITH_CACHE_TTL_SECONDS", 86400)
        self.WAPPALYZER_API_KEY = _get_optional_str("WAPPALYZER_API_KEY")
        self.WAPPALYZER_API_URL = _get_str("WAPPALYZER_API_URL", "https://api.wappalyzer.com")
        self.WAPPALYZER_ENABLED = _get_bool("WAPPALYZER_ENABLED", False)
        self.URLSCAN_API_KEY = _get_optional_str("URLSCAN_API_KEY")
        self.URLSCAN_API_URL = _get_str("URLSCAN_API_URL", "https://urlscan.io/api/v1")
        self.URLSCAN_ENABLED = _get_bool("URLSCAN_ENABLED", False)
        self.GREYNOISE_API_KEY = _get_optional_str("GREYNOISE_API_KEY")
        self.GREYNOISE_API_URL = _get_str("GREYNOISE_API_URL", "https://api.greynoise.io/v3")
        self.GREYNOISE_ENABLED = _get_bool("GREYNOISE_ENABLED", False)
        self.ALIENVAULT_OTX_API_KEY = _get_optional_str("ALIENVAULT_OTX_API_KEY")
        self.ALIENVAULT_OTX_API_URL = _get_str("ALIENVAULT_OTX_API_URL", "https://otx.alienvault.com/api/v1")
        self.ALIENVAULT_ENABLED = _get_bool("ALIENVAULT_ENABLED", False)
        self.CLOUDFLARE_API_KEY = _get_optional_str("CLOUDFLARE_API_KEY")
        self.CLOUDFLARE_API_URL = _get_str("CLOUDFLARE_API_URL", "https://api.cloudflare.com/client/v4")
        self.CLOUDFLARE_ENABLED = _get_bool("CLOUDFLARE_ENABLED", False)

        self.LLM_ENABLED = _get_bool("LLM_ENABLED", False)
        self.OPENAI_API_KEY = _get_first_optional_str(("OPENAI_API_KEY", "AI_API_KEY"))
        self.OPENAI_BASE_URL = _get_first_str(("OPENAI_BASE_URL", "OPENAI_API_BASE", "AI_API_BASE_URL"), "https://integrate.api.nvidia.com/v1")
        self.OPENAI_MODEL = _get_first_str(("OPENAI_MODEL", "OPENAI_API_MODEL", "AI_API_MODEL"), "gemma-2-27b-it")
        self.OPENAI_TIMEOUT_SECONDS = _get_float("OPENAI_TIMEOUT_SECONDS", 30.0)
        self.OPENAI_MAX_TOKENS = _get_int("OPENAI_MAX_TOKENS", 450)
        self.OPENAI_TEMPERATURE = _get_float("OPENAI_TEMPERATURE", 0.2)
        self.LLM_RATE_LIMIT = _get_str("LLM_RATE_LIMIT", "30/minute")
        self.AI_PRIMARY_PROVIDER = _get_str("AI_PRIMARY_PROVIDER", "nvidia")
        self.NVIDIA_API_KEY = _get_optional_str("NVIDIA_API_KEY")
        self.NVIDIA_MODEL = _get_str("NVIDIA_MODEL", "gemma-2-27b-it")
        self.NVIDIA_TIMEOUT_SECONDS = _get_float("NVIDIA_TIMEOUT_SECONDS", 25.0)
        self.AI_FALLBACK_PROVIDER = _get_str("AI_FALLBACK_PROVIDER", "openrouter")
        self.OPENROUTER_API_KEY = _get_optional_str("OPENROUTER_API_KEY")
        self.OPENROUTER_MODEL = _get_str("OPENROUTER_MODEL", "openai/gpt-oss-120b")
        self.OPENROUTER_TIMEOUT_SECONDS = _get_float("OPENROUTER_TIMEOUT_SECONDS", 35.0)

        self.REPORT_RENDERER = _get_str("REPORT_RENDERER", "playwright")
        self.PLAYWRIGHT_BROWSER_PATH = _get_optional_str("PLAYWRIGHT_BROWSER_PATH")
        self.REPORT_PDF_TIMEOUT_SECONDS = _get_int("REPORT_PDF_TIMEOUT_SECONDS", 120)
        self.REPORT_PDF_HEADER = _get_str("REPORT_PDF_HEADER", "VulNexus Security Report")
        self.REPORT_PDF_FOOTER = _get_str("REPORT_PDF_FOOTER", "Generated by VulNexus")

        self.INTELLIGENCE_CACHE_TTL_SECONDS = _get_int("INTELLIGENCE_CACHE_TTL_SECONDS", 3600)
        self.INTELLIGENCE_MAX_CONCURRENCY = _get_int("INTELLIGENCE_MAX_CONCURRENCY", 6)
        self.INTELLIGENCE_REQUEST_TIMEOUT_SECONDS = _get_int("INTELLIGENCE_REQUEST_TIMEOUT_SECONDS", 12)
        self.INTELLIGENCE_RETRY_ATTEMPTS = _get_int("INTELLIGENCE_RETRY_ATTEMPTS", 3)
        self.INTELLIGENCE_RETRY_BACKOFF_SECONDS = _get_float("INTELLIGENCE_RETRY_BACKOFF_SECONDS", 0.75)
        self.ENABLE_NVD_LOOKUP = _get_bool("ENABLE_NVD_LOOKUP", True)
        self.ENABLE_CIRCL_LOOKUP = _get_bool("ENABLE_CIRCL_LOOKUP", True)
        self.ENABLE_OSV_LOOKUP = _get_bool("ENABLE_OSV_LOOKUP", True)
        self.ENABLE_GITHUB_ADVISORY_LOOKUP = _get_bool("ENABLE_GITHUB_ADVISORY_LOOKUP", True)
        self.ENABLE_CISA_KEV_LOOKUP = _get_bool("ENABLE_CISA_KEV_LOOKUP", True)
        self.ENABLE_EPSS_LOOKUP = _get_bool("ENABLE_EPSS_LOOKUP", True)

        self.ML_MODEL_PATH = _get_str("ML_MODEL_PATH", "./ml_models/risk_model.joblib")
        self.ML_RETRAIN_ON_STARTUP = _get_bool("ML_RETRAIN_ON_STARTUP", False)

        self.LOG_LEVEL = _get_str("LOG_LEVEL", "INFO")
        self.RATE_LIMIT = _get_str("RATE_LIMIT", "100/minute")

        self.GOOGLE_CLIENT_ID = _get_optional_str("GOOGLE_CLIENT_ID")
        self.GOOGLE_CLIENT_SECRET = _get_optional_str("GOOGLE_CLIENT_SECRET")
        self.GOOGLE_REDIRECT_URI = _get_str("GOOGLE_REDIRECT_URI", "http://localhost:5173/auth/google/callback")

        self.GITHUB_CLIENT_ID = _get_optional_str("GITHUB_CLIENT_ID")
        self.GITHUB_CLIENT_SECRET = _get_optional_str("GITHUB_CLIENT_SECRET")
        self.GITHUB_REDIRECT_URI = _get_str("GITHUB_REDIRECT_URI", "http://localhost:5173/auth/github/callback")
        self.GITHUB_OAUTH_SCOPE = _get_str("GITHUB_OAUTH_SCOPE", "read:user user:email repo")

        self.CSRF_SECRET = _get_optional_str("CSRF_SECRET")
        self.ENCRYPTION_KEY = _get_optional_str("ENCRYPTION_KEY")
        self.METRICS_TOKEN = _get_optional_str("METRICS_TOKEN")
        self.SESSION_COOKIE_NAME = _get_str("SESSION_COOKIE_NAME", "vulnexus_refresh")
        self.SESSION_COOKIE_SECURE = _get_bool("SESSION_COOKIE_SECURE", self.IS_PRODUCTION)
        # Vercel and Railway deployments are commonly cross-site.  `lax`
        # cookies are not sent on fetch/XHR in that topology, causing refresh
        # to fail with a misleading 401 after the in-memory access token dies.
        self.SESSION_COOKIE_SAMESITE = _get_str(
            "SESSION_COOKIE_SAMESITE",
            "none" if self.IS_PRODUCTION else "lax",
        ).lower()
        self.SESSION_COOKIE_DOMAIN = _get_optional_str("SESSION_COOKIE_DOMAIN")
        self.SMTP_HOST = _get_optional_str("SMTP_HOST")
        self.SMTP_PORT = _get_int("SMTP_PORT", 587)
        self.SMTP_USERNAME = _get_optional_str("SMTP_USERNAME")
        self.SMTP_PASSWORD = _get_optional_str("SMTP_PASSWORD")
        self.SMTP_FROM_EMAIL = _get_optional_str("SMTP_FROM_EMAIL")
        self.PASSWORD_RESET_URL = _get_optional_str("PASSWORD_RESET_URL")
        self.EMAIL_VERIFICATION_URL = _get_optional_str("EMAIL_VERIFICATION_URL")
        self.REQUIRE_EMAIL_VERIFICATION = _get_bool("REQUIRE_EMAIL_VERIFICATION", self.IS_PRODUCTION)
        self.MFA_ISSUER = _get_str("MFA_ISSUER", "VulNexus")
        self.MFA_CHALLENGE_EXPIRE_MINUTES = _get_int("MFA_CHALLENGE_EXPIRE_MINUTES", 5)

        if self.IS_PRODUCTION:
            if not self.SECRET_KEY or len(self.SECRET_KEY) < 32 or self.SECRET_KEY.startswith(("dev-", "change-me")):
                raise RuntimeError("SECRET_KEY must be a unique, high-entropy value of at least 32 characters in production")
            if not self.CSRF_SECRET or len(self.CSRF_SECRET) < 32 or self.CSRF_SECRET.startswith(("dev-", "change-me")):
                raise RuntimeError("CSRF_SECRET must be a unique, high-entropy value of at least 32 characters in production")
            if not self.METRICS_TOKEN or len(self.METRICS_TOKEN) < 32:
                raise RuntimeError("METRICS_TOKEN must be configured in production")
            if not self.SMTP_HOST or not self.SMTP_FROM_EMAIL or not self.PASSWORD_RESET_URL or not self.EMAIL_VERIFICATION_URL:
                raise RuntimeError("SMTP_HOST, SMTP_FROM_EMAIL, PASSWORD_RESET_URL, and EMAIL_VERIFICATION_URL must be configured in production")
            if any("localhost" in origin or "127.0.0.1" in origin for origin in self.CORS_ORIGINS.split(",")):
                raise RuntimeError("CORS_ORIGINS must not contain local development origins in production")
            if self.SESSION_COOKIE_SAMESITE not in {"lax", "strict", "none"}:
                raise RuntimeError("SESSION_COOKIE_SAMESITE must be lax, strict, or none")
            if self.SESSION_COOKIE_SAMESITE == "none" and not self.SESSION_COOKIE_SECURE:
                raise RuntimeError("SESSION_COOKIE_SECURE must be enabled when SESSION_COOKIE_SAMESITE=none")

        # Development remains usable without a committed secret. Production never does.
        self.SECRET_KEY = self.SECRET_KEY or "development-only-not-for-deployment"
        self.CSRF_SECRET = self.CSRF_SECRET or "development-only-not-for-deployment"

    @staticmethod
    def _normalize_database_url(database_url: str) -> str:
        if database_url.startswith("postgresql://"):
            return database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        if database_url.startswith("postgresql+asyncpg://"):
            return database_url
        raise RuntimeError(
            "DATABASE_URL must use postgresql+asyncpg:// "
            "(postgresql:// is normalized automatically)"
        )


settings = Settings()
