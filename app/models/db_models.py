import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    Uuid,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanType(str, enum.Enum):
    FILE = "file"
    URL = "url"
    GITHUB = "github"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


class AIReviewStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"


class UserRole(str, enum.Enum):
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    QA_ENGINEER = "qa_engineer"
    DEVELOPER = "developer"
    TESTER = "tester"
    VIEWER = "viewer"


class ComplianceStandard(str, enum.Enum):
    OWASP_TOP_10 = "owasp_top_10"
    OWASP_ASVS = "owasp_asvs"
    NIST = "nist"
    CWE = "cwe"
    CVE = "cve"
    CVSS = "cvss"
    MITRE_ATTACK = "mitre_attack"
    CIS = "cis"


class ComplianceResult(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(32), default=UserRole.DEVELOPER.value, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    phone: Mapped[str] = mapped_column(String(64), default="")
    carrier: Mapped[str] = mapped_column(String(64), default="")
    fav_programming_languages: Mapped[list] = mapped_column(JSON, default=list)
    company: Mapped[str] = mapped_column(String(255), default="")
    job_role: Mapped[str] = mapped_column(String(255), default="")
    security_focus: Mapped[str] = mapped_column(String(255), default="")
    subscription_tier: Mapped[str] = mapped_column(String(64), default="free")
    subscription_status: Mapped[str] = mapped_column(String(64), default="active")
    subscription_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scan_limit: Mapped[int] = mapped_column(Integer, default=10)
    is_approved: Mapped[bool] = mapped_column(Boolean, default=True)
    pending_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    mpesa_number: Mapped[str] = mapped_column(String(64), default="")
    payment_method: Mapped[str] = mapped_column(String(64), default="")
    avatar_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    auth_provider: Mapped[str] = mapped_column(String(32), default="email")
    refresh_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    password_reset_token_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    password_reset_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verification_token_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    email_verification_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    email_verification_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    welcome_email_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    email_preferences: Mapped[dict] = mapped_column(JSON, default=dict)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_recovery_codes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    mfa_challenge_token_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mfa_challenge_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scans: Mapped[list["Scan"]] = relationship(back_populates="user")
    notifications: Mapped[list["Notification"]] = relationship(back_populates="user")
    oauth_accounts: Mapped[list["OAuthAccount"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    connected_github: Mapped[list["GitHubConnection"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    organization_memberships: Mapped[list["OrganizationMember"]] = relationship(back_populates="user", cascade="all, delete-orphan", foreign_keys="OrganizationMember.user_id")


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"), index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    owner: Mapped["User | None"] = relationship(foreign_keys=[owner_id])
    members: Mapped[list["OrganizationMember"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    projects: Mapped[list["Project"]] = relationship(back_populates="organization", cascade="all, delete-orphan")


class OrganizationMember(Base):
    __tablename__ = "organization_members"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.id"), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"), index=True)
    role: Mapped[str] = mapped_column(String(32), default=UserRole.DEVELOPER.value)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    organization: Mapped["Organization"] = relationship(back_populates="members")
    user: Mapped["User"] = relationship(back_populates="organization_memberships", foreign_keys=[user_id])

    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_org_member"),
    )


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.id"), index=True, nullable=True)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"), index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    organization: Mapped["Organization | None"] = relationship(back_populates="projects")
    owner: Mapped["User | None"] = relationship(foreign_keys=[owner_id])
    scans: Mapped[list["Scan"]] = relationship(back_populates="project")


class OAuthAccount(Base):
    __tablename__ = "oauth_accounts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"), index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    access_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    refresh_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    user: Mapped["User"] = relationship(back_populates="oauth_accounts")

    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_oauth_provider_user"),
    )


class GitHubConnection(Base):
    __tablename__ = "github_connections"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"), index=True, nullable=False)
    github_user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    github_username: Mapped[str] = mapped_column(String(255), nullable=False)
    access_token: Mapped[str] = mapped_column(Text, nullable=False)
    token_encrypted: Mapped[bool] = mapped_column(Boolean, default=True)
    connected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_connected: Mapped[bool] = mapped_column(Boolean, default=True)
    organizations: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    repositories: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    user: Mapped["User"] = relationship(back_populates="connected_github")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    target: Mapped[str] = mapped_column(String(1024), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"), index=True)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.id"), index=True, nullable=True)
    project_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("projects.id"), index=True, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default=ScanStatus.QUEUED.value, index=True)
    ai_review_status: Mapped[str] = mapped_column(String(32), default=AIReviewStatus.PENDING.value, index=True, nullable=False)
    ai_review_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    overall_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    github_org: Mapped[str | None] = mapped_column(String(255), nullable=True)
    github_repo: Mapped[str | None] = mapped_column(String(255), nullable=True)
    github_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    github_folder: Mapped[str | None] = mapped_column(String(512), nullable=True)

    user: Mapped["User | None"] = relationship(back_populates="scans")
    organization: Mapped["Organization | None"] = relationship()
    project: Mapped["Project | None"] = relationship(back_populates="scans")
    files: Mapped[list["ScanFile"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    ml_features: Mapped[list["MLFeature"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanFile(Base):
    __tablename__ = "scan_files"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("scans.id"), index=True)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    features_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="files")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("scans.id"), index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    code_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default=FindingStatus.OPEN.value, index=True)
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"), index=True, nullable=True)
    compliance_results: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    cwe_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    nist_control: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(128), nullable=True)
    known_exploit: Mapped[bool] = mapped_column(Boolean, default=False)
    references: Mapped[list | None] = mapped_column(JSON, nullable=True)
    ai_explanation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ai_explanation_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    scan: Mapped["Scan"] = relationship(back_populates="vulnerabilities")
    assigned_to: Mapped["User | None"] = relationship(foreign_keys=[assigned_to_id])
    comments: Mapped[list["FindingComment"]] = relationship(back_populates="vulnerability", cascade="all, delete-orphan")
    history: Mapped[list["FindingHistory"]] = relationship(back_populates="vulnerability", cascade="all, delete-orphan")


class FindingComment(Base):
    __tablename__ = "finding_comments"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("vulnerabilities.id"), index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="comments")
    user: Mapped["User | None"] = relationship()


class FindingHistory(Base):
    __tablename__ = "finding_history"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("vulnerabilities.id"), index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    from_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    to_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="history")
    user: Mapped["User | None"] = relationship()


class CVEEntry(Base):
    __tablename__ = "cve_entries"

    cve_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    published_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    affected_software: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    references: Mapped[list | None] = mapped_column(JSON, nullable=True)
    known_exploits: Mapped[bool] = mapped_column(Boolean, default=False)
    mitigation: Mapped[str | None] = mapped_column(Text, nullable=True)


class MLFeature(Base):
    __tablename__ = "ml_features"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("scans.id"), index=True)
    features_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    label: Mapped[str | None] = mapped_column(String(64), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="ml_features")


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"), index=True, nullable=True)
    type: Mapped[str] = mapped_column(String(32), default="info")
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    user: Mapped["User | None"] = relationship(back_populates="notifications")

    @property
    def read(self) -> bool:
        return self.is_read

    @read.setter
    def read(self, value: bool) -> None:
        self.is_read = value


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"), index=True, nullable=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    user: Mapped["User | None"] = relationship()


class ComplianceCheck(Base):
    __tablename__ = "compliance_checks"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("scans.id"), index=True)
    standard: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
