import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, HttpUrl, field_validator


class ScanUploadResponse(BaseModel):
    scan_id: uuid.UUID
    status: str = "queued"


class ScanURLRequest(BaseModel):
    url: HttpUrl
    project_id: Optional[uuid.UUID] = None


class ScanStatusResponse(BaseModel):
    scan_id: uuid.UUID
    status: str
    ai_review_status: str = "pending"
    ai_review_error: Optional[str] = None
    progress: int
    stage: Optional[str] = None
    message: Optional[str] = None
    error_message: Optional[str] = None
    details: dict = Field(default_factory=dict)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class AIReviewStatusResponse(BaseModel):
    scan_id: uuid.UUID
    ai_review_status: str
    ai_review_error: Optional[str] = None
    review: Optional[dict] = None
    enhanced_report_ready: bool = False


class ScanHistoryItem(BaseModel):
    id: uuid.UUID
    type: str
    target: str
    status: str
    overall_score: Optional[float] = None
    vulnerability_count: int = 0
    queued_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class ReportListItem(BaseModel):
    id: uuid.UUID
    name: str
    type: str
    target: str
    date: Optional[str] = None
    status: str
    format: str = "PDF"


class ReportAIQuestionRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)

    @field_validator("question")
    @classmethod
    def question_must_contain_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("question must contain text")
        return value


class VulnerabilityListItem(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    severity: str
    target: str
    scan_id: uuid.UUID
    cve: str = "N/A"
    cvss: Optional[float] = None
    status: str = "open"
    discovered: Optional[datetime] = None
    remediation: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    assigned_to_id: Optional[uuid.UUID] = None
    assigned_to_name: Optional[str] = None


class VulnerabilityDetailOut(BaseModel):
    id: uuid.UUID
    name: str
    severity: str
    target: str
    endpoint: str
    cve: str
    cvss: float
    status: str
    discovered: str
    last_seen: str
    description: str
    impact: str
    remediation: str
    affected_versions: str
    references: list[str]
    evidence: str
    timeline: list[dict]
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    ml_score: Optional[float] = None
    scan_id: uuid.UUID
    assigned_to_id: Optional[uuid.UUID] = None
    assigned_to_name: Optional[str] = None
    owasp_category: Optional[str] = None
    nist_control: Optional[str] = None
    mitre_technique: Optional[str] = None
    cwe_ids: list[str] = Field(default_factory=list)
    known_exploit: bool = False
    ai_explanation: Optional[dict] = None
    comments: list[dict] = Field(default_factory=list)
    history: list[dict] = Field(default_factory=list)


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
    cvss_score: Optional[float] = None
    cwe_ids: list[str] | None = None
    owasp_category: Optional[str] = None
    nist_control: Optional[str] = None
    mitre_technique: Optional[str] = None
    known_exploit: bool = False
    references: list[str] | None = None
    status: str = "open"
    assigned_to_id: Optional[uuid.UUID] = None

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
    ai_review_status: str = "pending"
    ai_review_error: Optional[str] = None
    overall_score: Optional[float] = None
    vulnerabilities: list[VulnerabilityOut] = Field(default_factory=list)
    target: str
    type: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    metadata: dict = Field(default_factory=dict)


class DashboardResponse(BaseModel):
    total_scans: int
    completed_scans: int
    failed_scans: int
    vulnerabilities_by_severity: dict[str, int]
    recent_scans: list[dict]
    average_risk_score: Optional[float] = None
    top_vulnerabilities: list[dict] = Field(default_factory=list)
    scan_trend: list[dict] = Field(default_factory=list)
    projects: int = 0
    repositories: int = 0
    organizations: int = 0
    open_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    resolved_findings: int = 0
    ignored_findings: int = 0
    compliance_score: Optional[float] = None
    owasp_score: Optional[float] = None
    nist_score: Optional[float] = None
    cwe_score: Optional[float] = None
    final_audit_verdict: Optional[str] = None
    final_audit_reason: Optional[str] = None
    certificate_health: Optional[str] = None
    tls_health: Optional[str] = None
    repository_status: list[dict] = Field(default_factory=list)
    recent_reports: list[dict] = Field(default_factory=list)
    recent_ai_conversations: list[dict] = Field(default_factory=list)
    risk_heatmap: list[dict] = Field(default_factory=list)


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
    title: Optional[str] = None
    category: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    crypto_feature: Optional[str] = None
    confidence: float = 0.8
    confidence_label: str = "probable"
    default_severity: Optional[str] = None
    cvss_hint: Optional[float] = None
    requires_review: bool = False
    evidence: dict = Field(default_factory=dict)
    explanation: Optional[str] = None
    remediation: Optional[str] = None
    recommendation: Optional[str] = None
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_category: Optional[str] = None
    references: list[str] = Field(default_factory=list)


class MLPrediction(BaseModel):
    score: float = Field(ge=0, le=100)
    severity: str
    feature_importances: Optional[dict[str, float]] = None
