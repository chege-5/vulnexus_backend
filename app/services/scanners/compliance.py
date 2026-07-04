from __future__ import annotations

from app.services.audit_engine import RULE_PROFILE_MAP
from app.services.models.pipeline import CorrelatedFinding, ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner


class ComplianceScanner(TargetScanner):
    name = "compliance"
    supported_kinds = {"url", "file", "github", "repository"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        findings = []
        for rule_id, profile in RULE_PROFILE_MAP.items():
            findings.append(self._finding(
                finding_type="compliance",
                title=f"Compliance mapping for {rule_id}",
                description=f"Rule {rule_id} maps to {profile.get('owasp_category') or 'internal control'}",
                severity="Info",
                evidence=profile,
                location=target.value,
                confidence=0.5,
                raw_data=profile,
                target=target.value,
                tags=["compliance"],
            ))
        return ScannerResult(findings=findings[:5], metadata={"rules": len(RULE_PROFILE_MAP)})