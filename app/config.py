from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://postgres:Jimmy%402005@localhost:5432/vulnexus"
    ASYNC_DATABASE_URL: str = "postgresql+asyncpg://postgres:Jimmy%402005@localhost:5432/vulnexus"
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"
    SECRET_KEY: str = "dev-only-change-me"
    ALGORITHM: str = "HS256"
    
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost"

    UPLOAD_DIR: str = "./uploads"
    MAX_UPLOAD_SIZE_MB: int = 50
    MAX_ZIP_ENTRIES: int = 500

    MAX_ZIP_UNCOMPRESSED_MB: int = 200
    MAX_ZIP_RATIO: int = 100
    VERIFY_SCAN_TARGETS: bool = True

    NVD_API_KEY: Optional[str] = None
    SSL_LABS_API_URL: str = "https://api.ssllabs.com/api/v3"
    CVE_CIRCL_API_URL: str = "https://cve.circl.lu/api"
    MITRE_CVE_API_URL: str = "https://cveawg.mitre.org/api"

    SHODAN_API_KEY: Optional[str] = None
    SHODAN_ENABLED: bool = False
    VIRUSTOTAL_API_KEY: Optional[str] = None
    VIRUSTOTAL_ENABLED: bool = False
    CLOUDFLARE_API_KEY: Optional[str] = None
    CLOUDFLARE_ENABLED: bool = False

    LLM_ENABLED: bool = False
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_BASE_URL: str = "https://integrate.api.nvidia.com/v1"
    OPENAI_MODEL: str = "gemma-2-27b-it"

    ML_MODEL_PATH: str = "./ml_models/risk_model.joblib"
    ML_RETRAIN_ON_STARTUP: bool = False

    LOG_LEVEL: str = "INFO"
    RATE_LIMIT: str = "100/minute"

    # OAuth
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    GOOGLE_REDIRECT_URI: str = "http://localhost:5173/auth/google/callback"

    GITHUB_CLIENT_ID: Optional[str] = None
    GITHUB_CLIENT_SECRET: Optional[str] = None
    GITHUB_REDIRECT_URI: str = "http://localhost:5173/auth/github/callback"

    # Security
    CSRF_SECRET: str = "change-me-csrf-secret"
    ENCRYPTION_KEY: Optional[str] = None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()