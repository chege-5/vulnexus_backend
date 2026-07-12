from __future__ import annotations

from app.services.audit_engine import RULE_PROFILE_MAP
from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner


class ComplianceScanner(TargetScanner):
    name = "compliance"
    supported_kinds = {"url", "file", "github", "repository"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        return ScannerResult(
            findings=[],
            metadata={
                "rules": len(RULE_PROFILE_MAP),
                "note": "Compliance is evaluated from actual findings during persistence; this scanner only advertises supported mapping coverage.",
            },
        )
