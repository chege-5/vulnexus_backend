from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanTarget(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    kind: Literal["url", "file", "github", "ip", "domain", "repository"]
    value: str
    display_name: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanContext(BaseModel):
    scan_id: UUID
    scan_type: str
    user_id: UUID | None = None
    target: ScanTarget
    source_path: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)
    progress: int = 0
    stage: str = "queued"
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class RawFinding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    type: str
    title: str
    description: str
    severity: str = "Medium"
    evidence: dict[str, Any] = Field(default_factory=dict)
    location: str | None = None
    confidence: float = 0.5
    source: str = "scanner"
    tags: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    target: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class CorrelatedFinding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    group_key: str
    title: str
    description: str
    severity: str
    threat_category: str = "general"
    attack_surface_category: str = "unknown"
    risk_category: str = "medium"
    cwe_ids: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)
    related_assets: list[str] = Field(default_factory=list)
    related_technologies: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    capec: list[str] = Field(default_factory=list)
    possible_attack_paths: list[str] = Field(default_factory=list)
    possible_attack_scenarios: list[str] = Field(default_factory=list)
    potential_lateral_movement: list[str] = Field(default_factory=list)
    exploitation_difficulty: str = "moderate"
    detection_difficulty: str = "moderate"
    attack_chain_contribution: float = 0.0
    requires_cve_lookup: bool = False
    primary_source: str = "scanner"
    sources: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    evidence_items: list[dict[str, Any]] = Field(default_factory=list)
    related_finding_ids: list[UUID] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    raw_findings: list[RawFinding] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class IntelligenceResult(BaseModel):
    provider: str
    query: str
    success: bool = True
    cached: bool = False
    summary: str | None = None
    identifier: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    kev: bool | None = None
    vendor: str | None = None
    references: list[str] = Field(default_factory=list)
    exploitability: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    retrieved_at: datetime = Field(default_factory=_utcnow)


class EnrichedFinding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    finding: CorrelatedFinding
    intelligence: list[IntelligenceResult] = Field(default_factory=list)
    knowledge: dict[str, Any] = Field(default_factory=dict)
    graph_context: dict[str, Any] = Field(default_factory=dict)
    llm_context: dict[str, Any] = Field(default_factory=dict)
    cve_id: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    kev: bool = False
    vendor: str | None = None
    references: list[str] = Field(default_factory=list)
    exploitability: str | None = None
    risk_factors: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class RiskScore(BaseModel):
    score: float = Field(ge=0, le=100)
    severity: str
    rationale: str
    factors: dict[str, float] = Field(default_factory=dict)
    likelihood: float = Field(default=0.0, ge=0, le=100)
    priority: str = "normal"
    business_impact: float = Field(default=0.0, ge=0, le=100)
    technical_impact: float = Field(default=0.0, ge=0, le=100)
    operational_impact: float = Field(default=0.0, ge=0, le=100)
    confidentiality_impact: float = Field(default=0.0, ge=0, le=100)
    integrity_impact: float = Field(default=0.0, ge=0, le=100)
    availability_impact: float = Field(default=0.0, ge=0, le=100)
    fix_complexity: str = "moderate"
    urgency: str = "normal"
    estimated_time_to_exploit: str = "unknown"
    estimated_time_to_remediate: str = "unknown"
    breakdown: dict[str, Any] = Field(default_factory=dict)
    model: str = "deterministic"
    confidence: float = Field(default=0.5, ge=0, le=1)
    updated_at: datetime = Field(default_factory=_utcnow)


class ProviderResponse(BaseModel):
    provider: str
    query: str
    enabled: bool = True
    cached: bool = False
    success: bool = True
    status_code: int | None = None
    ttl_seconds: int | None = None
    normalized: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    retrieved_at: datetime = Field(default_factory=_utcnow)


class ScanProgress(BaseModel):
    scan_id: UUID
    status: str
    progress: int = Field(ge=0, le=100)
    stage: str = "queued"
    message: str | None = None
    current_step: int = 0
    total_steps: int = 0
    started_at: datetime | None = None
    updated_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None
    error_message: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)