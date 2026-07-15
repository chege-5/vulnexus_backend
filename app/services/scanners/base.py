from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import re
from typing import Any

from app.services.models.pipeline import RawFinding, ScanContext, ScanTarget


@dataclass(slots=True)
class ScannerResult:
    findings: list[RawFinding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class TargetScanner(ABC):
    name: str
    supported_kinds: set[str] = {"url", "file", "github", "repository"}

    def supports(self, target: ScanTarget) -> bool:
        return target.kind in self.supported_kinds

    @abstractmethod
    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        raise NotImplementedError

    def _finding(
        self,
        *,
        finding_type: str,
        title: str,
        description: str,
        severity: str = "Medium",
        evidence: dict[str, Any] | None = None,
        affected_asset: str | None = None,
        location: str | None = None,
        confidence: float = 0.5,
        confidence_label: str | None = None,
        status: str = "open",
        source: str | None = None,
        tags: list[str] | None = None,
        remediation: str | None = None,
        references: list[str] | None = None,
        compliance_mapping: dict[str, Any] | None = None,
        correlation_group: str | None = None,
        raw_data: dict[str, Any] | None = None,
        target: str | None = None,
    ) -> RawFinding:
        raw = dict(raw_data or {})
        # Every scanner finding carries a scanner-originated stable ID. This
        # remains distinct from correlation identifiers used later in the flow.
        raw.setdefault("rule_id", self._stable_rule_id(title))
        classification = str(raw.get("classification") or "unknown")
        mapping = compliance_mapping or {}
        if not mapping and raw.get("rule_id"):
            try:
                from app.services.audit_engine import RULE_PROFILE_MAP
                mapping = RULE_PROFILE_MAP.get(str(raw.get("rule_id")), {})
            except Exception:
                mapping = {}
        finding = RawFinding(
            type=finding_type,
            title=title,
            description=description,
            severity=severity,
            evidence=evidence or {},
            affected_asset=affected_asset or target or location,
            location=location,
            confidence=confidence,
            confidence_label=confidence_label,
            status=status,
            source=source or self.name,
            source_scanner=source or self.name,
            tags=tags or [],
            remediation=remediation,
            references=references or [],
            compliance_mapping=mapping,
            classification=classification,
            correlation_group=correlation_group,
            raw_data=raw,
            target=target,
        )
        if classification == "unknown":
            try:
                from app.services.finding_classifier import classify_raw_finding

                finding.classification = classify_raw_finding(finding).value
            except Exception:
                pass
        return finding

    def _stable_rule_id(self, title: str) -> str:
        scanner = re.sub(r"[^A-Z0-9]+", "-", self.name.upper()).strip("-") or "SCANNER"
        label = re.sub(r"[^A-Z0-9]+", "-", title.upper()).strip("-") or "FINDING"
        return f"VN-{scanner}-{label}"[:255]
