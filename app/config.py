from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BASE_DIR / ".env")


def _get_str(name: str, default: str) -> str:
    return os.getenv(name, default)


def _get_optional_str(name: str) -> Optional[str]:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return None
    return value


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
        self.DATABASE_URL = _get_str("DATABASE_URL", "postgresql+asyncpg://vulnexus:vulnexus@localhost:5432/vulnexusdb")
        self.DATABASE_URL = self._normalize_database_url(self.DATABASE_URL)
        self.ASYNC_DATABASE_URL = _get_str("ASYNC_DATABASE_URL", self.DATABASE_URL)
        self.ASYNC_DATABASE_URL = self._normalize_database_url(self.ASYNC_DATABASE_URL)
        self.REDIS_URL = _get_str("REDIS_URL", "redis://localhost:6379/0")
        self.CELERY_BROKER_URL = _get_str("CELERY_BROKER_URL", self.REDIS_URL)
        self.CELERY_RESULT_BACKEND = _get_str("CELERY_RESULT_BACKEND", self.REDIS_URL)
        self.SECRET_KEY = _get_optional_str("SECRET_KEY") or secrets.token_urlsafe(48)
        self.ALGORITHM = _get_str("ALGORITHM", "HS256")

        self.ACCESS_TOKEN_EXPIRE_MINUTES = _get_int("ACCESS_TOKEN_EXPIRE_MINUTES", 60)
        self.REFRESH_TOKEN_EXPIRE_DAYS = _get_int("REFRESH_TOKEN_EXPIRE_DAYS", 30)
        self.CORS_ORIGINS = _get_str("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost,https://vulnexus.vercel.app")

        self.UPLOAD_DIR = _get_str("UPLOAD_DIR", "./uploads")
        self.MAX_UPLOAD_SIZE_MB = _get_int("MAX_UPLOAD_SIZE_MB", 50)
        self.MAX_ZIP_ENTRIES = _get_int("MAX_ZIP_ENTRIES", 500)
        self.MAX_ZIP_UNCOMPRESSED_MB = _get_int("MAX_ZIP_UNCOMPRESSED_MB", 200)
        self.MAX_ZIP_RATIO = _get_int("MAX_ZIP_RATIO", 100)
        self.VERIFY_SCAN_TARGETS = _get_bool("VERIFY_SCAN_TARGETS", True)
        self.SCAN_TIMEOUT = _get_int("SCAN_TIMEOUT", 60)
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
        self.SHODAN_ENABLED = _get_bool("SHODAN_ENABLED", False)
        self.SHODAN_API_URL = _get_str("SHODAN_API_URL", "https://api.shodan.io")
        self.CENSYS_API_ID = _get_optional_str("CENSYS_API_ID")
        self.CENSYS_API_SECRET = _get_optional_str("CENSYS_API_SECRET")
        self.CENSYS_API_URL = _get_str("CENSYS_API_URL", "https://search.censys.io/api/v2")
        self.CENSYS_ENABLED = _get_bool("CENSYS_ENABLED", False)
        self.SECURITYTRAILS_API_KEY = _get_optional_str("SECURITYTRAILS_API_KEY")
        self.SECURITYTRAILS_API_URL = _get_str("SECURITYTRAILS_API_URL", "https://api.securitytrails.com/v1")
        self.SECURITYTRAILS_ENABLED = _get_bool("SECURITYTRAILS_ENABLED", False)
        self.VIRUSTOTAL_API_KEY = _get_optional_str("VIRUSTOTAL_API_KEY")
        self.VIRUSTOTAL_ENABLED = _get_bool("VIRUSTOTAL_ENABLED", False)
        self.VIRUSTOTAL_API_URL = _get_str("VIRUSTOTAL_API_URL", "https://www.virustotal.com/api/v3")
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
        self.OPENAI_API_KEY = _get_optional_str("OPENAI_API_KEY")
        self.OPENAI_BASE_URL = _get_str("OPENAI_BASE_URL", "https://integrate.api.nvidia.com/v1")
        self.OPENAI_MODEL = _get_str("OPENAI_MODEL", "gemma-2-27b-it")

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

        self.CSRF_SECRET = _get_str("CSRF_SECRET", "change-me-csrf-secret")
        self.ENCRYPTION_KEY = _get_optional_str("ENCRYPTION_KEY")

    @staticmethod
    def _normalize_database_url(database_url: str) -> str:
        if database_url.startswith("postgresql://"):
            return database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        if database_url.startswith("sqlite:///") and not database_url.startswith("sqlite+aiosqlite:///"):
            return database_url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
        if database_url.startswith(("postgresql+asyncpg://", "sqlite+aiosqlite:///")):
            return database_url
        raise RuntimeError(
            "DATABASE_URL must use postgresql+asyncpg:// or sqlite+aiosqlite:/// "
            "(postgresql:// and sqlite:/// are normalized automatically)"
        )


settings = Settings()
