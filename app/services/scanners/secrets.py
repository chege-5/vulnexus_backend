from __future__ import annotations

from pathlib import Path

from app.models.pydantic_models import CryptoFeatures
from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner
from app.services.file_scanner import scan_file_content


class SASTScanner(TargetScanner):
    """Runs syntax-aware source analysis plus secret detection for code scans."""

    name = "sast"
    supported_kinds = {"file", "github", "repository"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        source_files = list(context.options.get("source_files") or [])
        if not source_files:
            if context.source_path:
                source_files.append(context.source_path)
            elif target.kind == "file":
                source_files.append(target.value)

        findings = []
        for file_path in source_files:
            try:
                content = Path(file_path).read_text(errors="ignore")
            except Exception:
                continue
            vulnerabilities, _features = scan_file_content(content, file_path)
            for vuln in vulnerabilities:
                findings.append(self._finding(
                    finding_type="sast",
                    title=vuln.rule_id,
                    description=vuln.description,
                    severity=vuln.severity,
                    evidence={"rule_id": vuln.rule_id, **vuln.evidence},
                    location=f"{file_path}:{vuln.line_number}" if vuln.line_number else file_path,
                    confidence=vuln.confidence,
                    confidence_label=vuln.confidence_label,
                    remediation=vuln.remediation,
                    raw_data=vuln.model_dump(),
                    target=target.value,
                    tags=["sast", "source", "semantic-analysis", vuln.category or "security"],
                ))
        return ScannerResult(findings=findings, metadata={"files_scanned": len(source_files), "engine": "syntax-aware-semantic", "regex_detection": False})


# Compatibility for integrations importing the old misleading class name.
SecretsScanner = SASTScanner
