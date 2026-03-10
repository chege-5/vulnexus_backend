import uuid
from datetime import datetime
from sqlalchemy import String, Integer, Float, Text, DateTime, ForeignKey, JSON, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
import enum

from app.deps import Base


class ScanType(str, enum.Enum):
    FILE = "file"
    URL = "url"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scans: Mapped[list["Scan"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    type: Mapped[str] = mapped_column(SAEnum(ScanType), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.QUEUED)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    queued_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    overall_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    user: Mapped[User | None] = relationship(back_populates="scans")
    scan_files: Mapped[list["ScanFile"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    ml_features: Mapped[list["MLFeature"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanFile(Base):
    __tablename__ = "scan_files"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    features_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="scan_files")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(SAEnum(Severity), nullable=False)
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(50), ForeignKey("cve_entries.cve_id"), nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan: Mapped[Scan] = relationship(back_populates="vulnerabilities")
    cve_entry: Mapped["CVEEntry | None"] = relationship()


class CVEEntry(Base):
    __tablename__ = "cve_entries"

    cve_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    published_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_modified: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class MLFeature(Base):
    __tablename__ = "ml_features"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    features_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    label: Mapped[str | None] = mapped_column(String(50), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="ml_features")
