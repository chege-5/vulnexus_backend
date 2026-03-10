import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, HttpUrl


class ScanUploadResponse(BaseModel):
    scan_id: uuid.UUID
    status: str = "queued"


class ScanURLRequest(BaseModel):
    url: HttpUrl


class ScanStatusResponse(BaseModel):
    scan_id: uuid.UUID
    status: str
    progress: int
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class VulnerabilityOut(BaseModel):
    id: uuid.UUID
    rule_id: Optional[str] = None
    description: str
    severity: str
    ml_score: Optional[float] = None
    cve_id: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    remediation: Optional[str] = None

    class Config:
        from_attributes = True


class CVEOut(BaseModel):
    cve_id: str
    summary: Optional[str] = None
    cvss_score: Optional[float] = None
    published_date: Optional[datetime] = None

    class Config:
        from_attributes = True


class ScanResultResponse(BaseModel):
    scan_id: uuid.UUID
    status: str
    overall_score: Optional[float] = None
    vulnerabilities: list[VulnerabilityOut] = Field(default_factory=list)
    target: str
    type: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class DashboardResponse(BaseModel):
    total_scans: int
    completed_scans: int
    failed_scans: int
    vulnerabilities_by_severity: dict[str, int]
    recent_scans: list[dict]
    average_risk_score: Optional[float] = None


class CryptoFeatures(BaseModel):
    key_size: Optional[int] = None
    hash_algorithm: Optional[str] = None
    cipher_mode: Optional[str] = None
    tls_version: Optional[str] = None
    cert_valid_days: Optional[int] = None
    forward_secrecy: Optional[bool] = None
    rule_score: float = 0.0
    uses_md5: bool = False
    uses_sha1: bool = False
    uses_des: bool = False
    uses_rc2: bool = False
    uses_ecb: bool = False
    rsa_key_small: bool = False
    aes_key_small: bool = False
    hardcoded_key: bool = False
    insecure_random: bool = False
    has_hsts: Optional[bool] = None
    self_signed: Optional[bool] = None


class RuleVulnerability(BaseModel):
    rule_id: str
    description: str
    severity: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    crypto_feature: Optional[str] = None


class MLPrediction(BaseModel):
    score: float = Field(ge=0, le=100)
    severity: str
    feature_importances: Optional[dict[str, float]] = None
