from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://vulnexus:vulnexus_secret@localhost:5432/vulnexus"
    SYNC_DATABASE_URL: str = "postgresql+psycopg://vulnexus:vulnexus_secret@localhost:5432/vulnexus"
    REDIS_URL: str = "redis://localhost:6379/0"
    SECRET_KEY: str = "change-me-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

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
    OPENAI_MODEL: str = "gpt-4"

    ML_MODEL_PATH: str = "./ml_models/risk_model.joblib"
    ML_RETRAIN_ON_STARTUP: bool = False

    LOG_LEVEL: str = "INFO"
    RATE_LIMIT: str = "100/minute"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
