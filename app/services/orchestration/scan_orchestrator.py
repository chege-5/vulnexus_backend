from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import select

from app import database
from app.config import settings
from app.models.db_models import CVEEntry, ComplianceCheck, MLFeature, Scan, ScanFile, ScanStatus, Severity, Vulnerability
from app.services.ai.risk_engine import AIRiskEngine
from app.services.audit_engine import build_ai_insight, build_compliance_checks, derive_final_audit_verdict, infer_vulnerability_profile
from app.services.correlation.engine import CorrelationEngine
from app.services.github_repo_scanner import materialize_repository_source
from app.services.models.pipeline import RawFinding, ScanContext, ScanProgress, ScanTarget
from app.services.report_generator import build_report, get_remediation
from app.services.scanners.compliance import ComplianceScanner
from app.services.scanners.dependency import DependencyScanner
from app.services.scanners.dns import DNSScanner
from app.services.scanners.github_repository import GitHubRepositoryScanner
from app.services.scanners.headers import HeaderScanner
from app.services.scanners.reputation import ReputationScanner
from app.services.scanners.secrets import SecretsScanner
from app.services.scanners.technology import TechnologyFingerprintScanner
from app.services.scanners.tls import TLSScanner
from app.services.scanners.web_crawl import WebCrawlScanner
from app.utils.cache import cache
from app.utils.crypto import decrypt_token
from app.utils.file_utils import extract_zip
from app.utils.logger import get_logger, timed_stage

logger = get_logger(__name__)


@dataclass(slots=True)
class ScanExecutionPlan:
    scanners: list[Any] = field(default_factory=list)
    parallel_groups: list[list[Any]] = field(default_factory=list)


class ScanOrchestrator:
    def __init__(self) -> None:
        self.correlation_engine = CorrelationEngine()
        self.ai_engine = AIRiskEngine()
        self._scanner_instances = {
            "tls": TLSScanner(),
            "headers": HeaderScanner(),
            "dns": DNSScanner(),
            "technology": TechnologyFingerprintScanner(),
            "reputation": ReputationScanner(),
            "secrets": SecretsScanner(),
            "dependency": DependencyScanner(),
            "github": GitHubRepositoryScanner(),
            "web_crawl": WebCrawlScanner(),
            "compliance": ComplianceScanner(),
        }

    async def execute(self, scan_id: UUID, *, source_path: str | None = None, user_id: UUID | None = None, options: dict[str, Any] | None = None) -> dict[str, Any]:
        options = options or {}
        async with database.async_session_maker() as db:
            scan = await self._load_scan(db, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            target = self._build_target(scan, source_path=source_path, options=options)
            context = ScanContext(
                scan_id=scan.id,
                scan_type=scan.type,
                user_id=user_id or scan.user_id,
                target=target,
                source_path=source_path,
                options=options,
                stage="queued",
                progress=0,
            )

            await self._mark_scan(db, scan, status=ScanStatus.IN_PROGRESS.value, started_at=datetime.now(timezone.utc), progress=5)
            await self._store_progress(context, status=ScanStatus.IN_PROGRESS.value, message="Scan started", progress=5)

            raw_findings: list[RawFinding] = []
            if scan.type == "file":
                raw_findings.extend(await self._execute_file_pipeline(context))
            elif scan.type == "url":
                raw_findings.extend(await self._execute_url_pipeline(context))
            elif scan.type == "github":
                raw_findings.extend(await self._execute_github_pipeline(context))
            else:
                raise ValueError(f"Unsupported scan type: {scan.type}")

            await self._store_progress(context, status=ScanStatus.IN_PROGRESS.value, message="Correlating findings", progress=70)
            correlated = await self.correlation_engine.correlate(raw_findings)

            await self._store_progress(context, status=ScanStatus.IN_PROGRESS.value, message="Calculating risk", progress=80)
            risk = self.ai_engine.evaluate(correlated)

            await self._persist_results(db, scan, context, correlated, risk)

            await self._mark_scan(db, scan, status=ScanStatus.COMPLETED.value, progress=100, overall_score=risk.score, finished_at=datetime.now(timezone.utc))
            await self._store_progress(context, status=ScanStatus.COMPLETED.value, message="Scan completed", progress=100, finished_at=datetime.now(timezone.utc))

            return {
                "scan_id": str(scan.id),
                "status": ScanStatus.COMPLETED.value,
                "overall_score": risk.score,
                "risk": risk.model_dump(),
                "findings": [item.model_dump() for item in correlated],
            }

    async def _execute_url_pipeline(self, context: ScanContext) -> list[RawFinding]:
        scanners = [self._scanner_instances["tls"], self._scanner_instances["headers"], self._scanner_instances["dns"], self._scanner_instances["technology"], self._scanner_instances["reputation"], self._scanner_instances["web_crawl"], self._scanner_instances["compliance"]]
        results = await self._run_scanners(scanners, context)
        return [finding for result in results for finding in result.findings]

    async def _execute_file_pipeline(self, context: ScanContext) -> list[RawFinding]:
        source_path = Path(context.source_path or context.target.value)
        if source_path.suffix.lower() == ".zip":
            extract_dir = Path(settings.UPLOAD_DIR) / str(context.scan_id) / "extracted"
            extract_dir.mkdir(parents=True, exist_ok=True)
            extracted = extract_zip(str(source_path), str(extract_dir))
            context = context.model_copy(update={"source_path": str(extract_dir), "options": {**context.options, "source_files": extracted}})
            source_path = extract_dir
        else:
            extracted = [str(source_path)]
            context = context.model_copy(update={"options": {**context.options, "source_files": extracted}})

        for path in extracted:
            async with database.async_session_maker() as db:
                db.add(ScanFile(scan_id=context.scan_id, filename=Path(path).name, path=path))
                await db.commit()

        scanners = [self._scanner_instances["secrets"], self._scanner_instances["dependency"], self._scanner_instances["compliance"]]
        results = await self._run_scanners(scanners, context)
        return [finding for result in results for finding in result.findings]

    async def _execute_github_pipeline(self, context: ScanContext) -> list[RawFinding]:
        github_scanner = self._scanner_instances["github"]
        repository_result = await github_scanner.scan(context.target, context)
        source_files = repository_result.metadata.get("source_files") or []
        for path in source_files:
            async with database.async_session_maker() as db:
                db.add(ScanFile(scan_id=context.scan_id, filename=Path(path).name, path=path))
                await db.commit()

        context = context.model_copy(update={"source_path": repository_result.metadata.get("scan_root") or context.source_path, "options": {**context.options, "source_files": source_files}})
        scanners = [self._scanner_instances["secrets"], self._scanner_instances["dependency"], self._scanner_instances["compliance"]]
        results = await self._run_scanners([github_scanner, *scanners], context)
        return [finding for result in results for finding in result.findings]

    async def _run_scanners(self, scanners: list[Any], context: ScanContext) -> list[Any]:
        if settings.ENABLE_PARALLEL_SCANNERS:
            tasks = [scanner.scan(context.target, context) for scanner in scanners if scanner.supports(context.target)]
            return await asyncio.gather(*tasks)
        results = []
        for scanner in scanners:
            if scanner.supports(context.target):
                results.append(await scanner.scan(context.target, context))
        return results

    async def _persist_results(self, db, scan: Scan, context: ScanContext, findings: list[Any], risk) -> None:
        enriched_vulnerabilities = []
        cve_entries: dict[str, CVEEntry] = {}
        known_exploit_count = 0
        vulnerability_payloads = []

        for finding in findings:
            remediation_key = finding.finding.raw_findings[0].raw_data.get("rule_id") if finding.finding.raw_findings else finding.finding.group_key
            remediation = get_remediation(remediation_key)
            profile = infer_vulnerability_profile(finding.finding.group_key, finding.finding.severity, cve_id=finding.cve_id, cvss_score=finding.cvss_score)
            if profile.get("known_exploit"):
                known_exploit_count += 1

            vuln = Vulnerability(
                scan_id=scan.id,
                rule_id=finding.finding.group_key,
                description=finding.finding.description,
                severity=self._map_severity(finding.finding.severity),
                ml_score=risk.score,
                file_path=finding.finding.evidence.get("file_path") or finding.finding.evidence.get("location"),
                line_number=finding.finding.evidence.get("line_number"),
                remediation=remediation,
                cve_id=finding.cve_id,
                cvss_score=finding.cvss_score,
                cwe_ids=finding.finding.cwe_ids,
                owasp_category=profile.get("owasp_category"),
                nist_control=profile.get("nist_control"),
                mitre_technique=profile.get("mitre_technique"),
                known_exploit=bool(profile.get("known_exploit")),
                references=finding.references or None,
                compliance_results={"owasp_top_10": profile.get("owasp_category"), "nist": profile.get("nist_control"), "cwe": finding.finding.cwe_ids},
            )
            db.add(vuln)
            vulnerability_payloads.append({
                "rule_id": vuln.rule_id,
                "description": vuln.description,
                "severity": finding.finding.severity,
                "ml_score": risk.score,
                "file_path": vuln.file_path,
                "line_number": vuln.line_number,
                "remediation": remediation,
                "cve_id": finding.cve_id,
                "cvss_score": finding.cvss_score,
                "cwe_ids": finding.finding.cwe_ids,
                "owasp_category": profile.get("owasp_category"),
                "nist_control": profile.get("nist_control"),
                "mitre_technique": profile.get("mitre_technique"),
                "known_exploit": bool(profile.get("known_exploit")),
            })

            if finding.cve_id and finding.cve_id not in cve_entries:
                cve_entries[finding.cve_id] = CVEEntry(cve_id=finding.cve_id, summary=finding.intelligence[0].summary if finding.intelligence else None, cvss_score=finding.cvss_score, published_date=None, references=finding.references or None)

        for entry in cve_entries.values():
            await db.merge(entry)

        compliance_checks = build_compliance_checks(vulnerability_payloads, [
            {
                "cve_id": entry.cve_id,
                "summary": entry.summary,
                "cvss_score": entry.cvss_score,
                "published_date": entry.published_date.isoformat() if entry.published_date else None,
                "references": entry.references or [],
            }
            for entry in cve_entries.values()
        ])
        for item in compliance_checks:
            db.add(ComplianceCheck(scan_id=scan.id, standard=item["standard"], category=item.get("category"), result=item["result"], score=item.get("score"), details=item.get("details")))

        db.add(MLFeature(scan_id=scan.id, features_json={"risk_score": risk.model_dump(), "findings": len(findings)}, label=risk.severity))
        await db.commit()

        final_verdict = derive_final_audit_verdict(
            overall_score=risk.score,
            compliance_score=self._compliance_score(compliance_checks),
            critical_findings=sum(1 for item in vulnerability_payloads if item["severity"] == "Critical"),
            high_findings=sum(1 for item in vulnerability_payloads if item["severity"] == "High"),
            cve_count=sum(1 for item in vulnerability_payloads if item.get("cve_id")),
            known_exploit_count=known_exploit_count,
        )
        ai_insight = build_ai_insight(
            target=scan.target,
            scan_type=scan.type,
            overall_score=risk.score,
            compliance_score=self._compliance_score(compliance_checks),
            verdict=final_verdict,
            vulnerabilities=vulnerability_payloads,
        )
        await asyncio.to_thread(
            build_report,
            scan_id=scan.id,
            target=scan.target,
            scan_type=scan.type,
            overall_score=risk.score,
            vulnerabilities=vulnerability_payloads,
            cve_details=[{"cve_id": entry.cve_id, "summary": entry.summary, "cvss_score": entry.cvss_score, "published_date": entry.published_date.isoformat() if entry.published_date else None, "references": entry.references or []} for entry in cve_entries.values()],
            compliance_checks=compliance_checks,
            audit_verdict=final_verdict,
            ai_insight=ai_insight,
            started_at=scan.started_at,
            finished_at=datetime.now(timezone.utc),
        )

    async def _load_scan(self, db, scan_id: UUID):
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        return result.scalar_one_or_none()

    def _build_target(self, scan: Scan, *, source_path: str | None, options: dict[str, Any]) -> ScanTarget:
        kind = "url" if scan.type == "url" else "file" if scan.type == "file" else "github"
        metadata = {"scan_type": scan.type, **options}
        if scan.type == "github":
            metadata.update({"owner": scan.github_org, "repository": scan.github_repo, "branch": scan.github_branch, "folder": scan.github_folder})
        return ScanTarget(kind=kind, value=scan.target, display_name=scan.target, metadata=metadata)

    async def _mark_scan(self, db, scan: Scan, **updates) -> None:
        for key, value in updates.items():
            if value is not None:
                setattr(scan, key, value)
        await db.commit()

    async def _store_progress(self, context: ScanContext, **updates) -> None:
        progress = ScanProgress(scan_id=context.scan_id, status=updates.get("status", "queued"), progress=updates.get("progress", context.progress), stage=updates.get("stage", context.stage), message=updates.get("message"), started_at=updates.get("started_at"), finished_at=updates.get("finished_at"), error_message=updates.get("error_message"), details=updates.get("details", {}))
        await cache.set("scan_progress", str(context.scan_id), progress.model_dump())

    def _map_severity(self, severity: str) -> str:
        mapping = {"Info": Severity.LOW.value, "Low": Severity.LOW.value, "Medium": Severity.MEDIUM.value, "High": Severity.HIGH.value, "Critical": Severity.CRITICAL.value}
        return mapping.get(severity, Severity.MEDIUM.value)

    def _compliance_score(self, compliance_checks: list[dict[str, Any]]) -> float | None:
        if not compliance_checks:
            return None
        passed = sum(1 for item in compliance_checks if item["result"] == "pass")
        return round((passed / len(compliance_checks)) * 100, 2)


scan_orchestrator = ScanOrchestrator()