from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError

from app import database
from app.config import settings
from app.models.db_models import AIReviewStatus, CVEEntry, ComplianceCheck, Scan, ScanFile, ScanStatus, Severity, Vulnerability
from app.services.ai.risk_engine import AIRiskEngine
from app.services.ai.explanations import ai_explanation_service
from app.services.audit_engine import build_compliance_checks, derive_final_audit_verdict, infer_vulnerability_profile
from app.services.correlation.engine import CorrelationEngine
from app.services.intelligence import knowledge_engine
from app.services.models.pipeline import CorrelatedFinding, EnrichedFinding, RawFinding, ScanContext, ScanProgress, ScanTarget
from app.services.report_generator import build_report, get_remediation
from app.services.scanners.base import ScannerResult
from app.services.scanners.compliance import ComplianceScanner
from app.services.scanners.dependency import DependencyScanner
from app.services.scanners.dns import DNSScanner
from app.services.scanners.github_repository import GitHubRepositoryScanner
from app.services.scanners.headers import HeaderScanner
from app.services.scanners.reputation import ReputationScanner
from app.services.scanners.secrets import SASTScanner
from app.services.scanners.technology import TechnologyFingerprintScanner
from app.services.scanners.tls import TLSScanner
from app.services.scanners.web_crawl import WebCrawlScanner
from app.utils.cache import cache
from app.utils.crypto import decrypt_token
from app.utils.file_utils import extract_zip
from app.utils.logger import get_logger, timed_stage
from app.utils.redaction import redact_data, redact_text

logger = get_logger(__name__)


BOUNDED_VULNERABILITY_FIELDS = {
    "severity": 32,
    "rule_id": 255,
    "cve_id": 64,
    "status": 32,
    "owasp_category": 128,
    "nist_control": 128,
    "mitre_technique": 128,
}

RULE_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9_-]{1,254}$")


class ScanPersistenceError(RuntimeError):
    pass


@dataclass(slots=True)
class NormalizedField:
    value: str | None
    changed: bool = False


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
            "sast": SASTScanner(),
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

            # Late acknowledgements may redeliver an already-completed task.
            # A retry must not rerun a terminal scan or append duplicate rows.
            if scan.status in {ScanStatus.COMPLETED.value, ScanStatus.CANCELED.value}:
                logger.info("Ignoring redelivered terminal scan task scan_id=%s status=%s", scan_id, scan.status)
                return {"scan_id": str(scan.id), "status": scan.status, "idempotent": True}
            if scan.status == ScanStatus.IN_PROGRESS.value:
                logger.info("Ignoring concurrent scan execution scan_id=%s", scan_id)
                return {"scan_id": str(scan.id), "status": scan.status, "idempotent": True}

            logger.info("Scan start scan_id=%s type=%s", scan_id, scan.type)

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
            await self._raise_if_canceled(scan.id)

            raw_findings: list[RawFinding] = []
            if scan.type == "file":
                raw_findings.extend(await self._execute_file_pipeline(context))
            elif scan.type == "url":
                raw_findings.extend(await self._execute_url_pipeline(context))
            elif scan.type == "github":
                raw_findings.extend(await self._execute_github_pipeline(context))
            else:
                raise ValueError(f"Unsupported scan type: {scan.type}")
            logger.info("Scanner completion scan_id=%s findings=%s", scan_id, len(raw_findings))

            await self._raise_if_canceled(scan.id)
            await self._store_progress(context, status=ScanStatus.IN_PROGRESS.value, message="Correlating findings", progress=70)
            correlated = await self.correlation_engine.correlate(raw_findings)
            displayed = self._display_findings(raw_findings, correlated)
            logger.info(
                "Correlation complete scan_id=%s raw_findings=%s displayed_findings=%s correlated_vulnerabilities=%s score_inputs=%s",
                scan_id,
                len(raw_findings),
                len(displayed),
                len(correlated),
                len(correlated),
            )

            await self._raise_if_canceled(scan.id)
            await self._store_progress(context, status=ScanStatus.IN_PROGRESS.value, message="Calculating risk", progress=80)
            risk = self.ai_engine.evaluate(correlated)

            await self._raise_if_canceled(scan.id)
            # The deterministic scan must finish independently. AI enrichment,
            # remediation review, and enhanced reporting run only after this
            # baseline has been committed and marked completed.
            await self._store_progress(context, status=ScanStatus.IN_PROGRESS.value, message="Saving findings", progress=88)
            enriched = [EnrichedFinding(finding=item) for item in displayed]

            try:
                await self._persist_results(db, scan, context, enriched, risk)
            except Exception as exc:
                await db.rollback()
                finished_at = datetime.now(timezone.utc)
                message = self._persistence_error_message(exc)
                await self._mark_scan(
                    db,
                    scan,
                    status=ScanStatus.FAILED.value,
                    progress=max(scan.progress or 0, 88),
                    error_message=message,
                    finished_at=finished_at,
                )
                await self._store_progress(
                    context,
                    status=ScanStatus.FAILED.value,
                    message="Scan failed while saving findings",
                    progress=max(scan.progress or 0, 88),
                    error_message=message,
                    finished_at=finished_at,
                )
                raise ScanPersistenceError(message) from exc

            # Retain the correlated context needed for the post-completion
            # intelligence review without exposing it through the result API.
            try:
                metadata = dict(scan.result_metadata or {})
                metadata["_ai_review_context"] = [item.model_dump(mode="json") for item in displayed]
                scan.result_metadata = metadata
                await db.commit()
            except Exception:
                await db.rollback()
                logger.exception("Unable to save AI review context scan_id=%s", scan.id)

            finished_at = datetime.now(timezone.utc)
            await self._mark_scan(
                db,
                scan,
                status=ScanStatus.COMPLETED.value,
                ai_review_status=AIReviewStatus.PENDING.value,
                ai_review_error=None,
                progress=100,
                overall_score=risk.score,
                finished_at=finished_at,
            )
            await self._store_progress(context, status=ScanStatus.COMPLETED.value, message="Scan completed", progress=100, finished_at=finished_at)
            await self._queue_ai_review(db, scan)

            return {
                "scan_id": str(scan.id),
                "status": ScanStatus.COMPLETED.value,
                "overall_score": risk.score,
                "risk": risk.model_dump(),
                "findings": [item.model_dump() for item in enriched],
                "metadata": scan.result_metadata or {},
            }

    def _display_findings(self, raw_findings: list[RawFinding], correlated: list[CorrelatedFinding]) -> list[CorrelatedFinding]:
        """Keep each raw scanner result visible while retaining correlation for risk."""
        memberships = {
            raw.id: incident
            for incident in correlated
            for raw in incident.raw_findings
        }
        displayed: list[CorrelatedFinding] = []
        for raw in raw_findings:
            parent = memberships.get(raw.id)
            rule_id = str(raw.raw_data.get("rule_id") or raw.evidence.get("rule_id") or "VN-SCANNER-FINDING")
            displayed.append(
                CorrelatedFinding(
                    group_key=f"raw:{raw.id}",
                    correlation_id=parent.correlation_id if parent else None,
                    contributing_rule_ids=[rule_id],
                    title=raw.title,
                    description=raw.description,
                    severity=raw.severity,
                    threat_category=parent.threat_category if parent else "general",
                    attack_surface_category=parent.attack_surface_category if parent else "unknown",
                    risk_category=parent.risk_category if parent else "medium",
                    classification=raw.classification,
                    cwe_ids=parent.cwe_ids if parent else [],
                    related_cves=parent.related_cves if parent else [],
                    related_assets=[value for value in [raw.affected_asset, raw.target, raw.location] if value],
                    related_technologies=parent.related_technologies if parent else [],
                    mitre_attack=parent.mitre_attack if parent else [],
                    capec=parent.capec if parent else [],
                    possible_attack_paths=parent.possible_attack_paths if parent else [],
                    possible_attack_scenarios=parent.possible_attack_scenarios if parent else [],
                    potential_lateral_movement=parent.potential_lateral_movement if parent else [],
                    exploitation_difficulty=parent.exploitation_difficulty if parent else "moderate",
                    detection_difficulty=parent.detection_difficulty if parent else "moderate",
                    attack_chain_contribution=parent.attack_chain_contribution if parent else 0.0,
                    requires_cve_lookup=parent.requires_cve_lookup if parent else False,
                    primary_source=raw.source,
                    sources=[raw.source],
                    evidence={**raw.evidence, **raw.raw_data},
                    evidence_items=[{"title": raw.title, "rule_id": rule_id, "severity": raw.severity, "location": raw.location}],
                    tags=raw.tags,
                    confidence=raw.confidence,
                    raw_findings=[raw],
                )
            )
        return displayed

    async def _execute_url_pipeline(self, context: ScanContext) -> list[RawFinding]:
        scanners = [self._scanner_instances["tls"], self._scanner_instances["headers"], self._scanner_instances["dns"], self._scanner_instances["technology"], self._scanner_instances["reputation"], self._scanner_instances["web_crawl"], self._scanner_instances["compliance"]]
        results = await self._run_scanners(scanners, context)
        for scanner, result in zip(scanners, results):
            if scanner.name == "reputation":
                context.options["scan_result_metadata"] = {"reputation": result.metadata}
                break
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

        scanners = [self._scanner_instances["sast"], self._scanner_instances["dependency"], self._scanner_instances["compliance"]]
        results = await self._run_scanners(scanners, context)
        sast_result = next((result for scanner, result in zip(scanners, results) if scanner.name == "sast"), None)
        logger.info(
            "File SAST complete scan_id=%s files=%s findings=%s engine=%s",
            context.scan_id,
            len(extracted),
            len(sast_result.findings) if sast_result else 0,
            (sast_result.metadata or {}).get("engine") if sast_result else "unavailable",
        )
        return [finding for result in results for finding in result.findings]

    async def _execute_github_pipeline(self, context: ScanContext) -> list[RawFinding]:
        github_scanner = self._scanner_instances["github"]
        repository_result = await self._scan_safe(github_scanner, context)
        source_files = repository_result.metadata.get("source_files") or []
        for path in source_files:
            async with database.async_session_maker() as db:
                db.add(ScanFile(scan_id=context.scan_id, filename=Path(path).name, path=path))
                await db.commit()

        context = context.model_copy(update={"source_path": repository_result.metadata.get("scan_root") or context.source_path, "options": {**context.options, "source_files": source_files}})
        scanners = [self._scanner_instances["sast"], self._scanner_instances["dependency"], self._scanner_instances["compliance"]]
        results = await self._run_scanners([github_scanner, *scanners], context)
        return [finding for result in results for finding in result.findings]

    async def _run_scanners(self, scanners: list[Any], context: ScanContext) -> list[Any]:
        if settings.ENABLE_PARALLEL_SCANNERS:
            tasks = [self._scan_safe(scanner, context) for scanner in scanners if scanner.supports(context.target)]
            results = await asyncio.gather(*tasks)
            logger.info("Scanner group complete scan_id=%s scanners=%s", context.scan_id, len(results))
            return results
        results = []
        for scanner in scanners:
            if scanner.supports(context.target):
                results.append(await self._scan_safe(scanner, context))
                logger.info("Scanner complete scan_id=%s scanner=%s", context.scan_id, getattr(scanner, "name", scanner.__class__.__name__))
        return results

    async def _scan_safe(self, scanner, context: ScanContext) -> ScannerResult:
        try:
            return await scanner.scan(context.target, context)
        except Exception as exc:
            scanner_name = getattr(scanner, "name", scanner.__class__.__name__)
            logger.warning("Scanner %s failed for scan %s: %s", scanner_name, context.scan_id, exc)
            return ScannerResult(findings=[], metadata={"scanner": scanner_name, "error": str(exc), "failed": True})

    async def _persist_results(self, db, scan: Scan, context: ScanContext, findings: list[EnrichedFinding], risk) -> None:
        # Queue-time target provenance is security-relevant and must survive
        # completion.  Scanner metadata (for example provider statuses) is
        # additive rather than a replacement for it.
        scan.result_metadata = {
            **(scan.result_metadata or {}),
            **(context.options.get("scan_result_metadata") or {}),
        }
        # Delete-and-replace makes a recovery from a failed persistence attempt
        # deterministic without changing finding IDs for a completed scan (which
        # is never re-executed above).  The delete and replacement share one
        # transaction, so a commit failure rolls both back.
        await db.execute(delete(Vulnerability).where(Vulnerability.scan_id == scan.id))
        await db.execute(delete(ComplianceCheck).where(ComplianceCheck.scan_id == scan.id))

        cve_entries: dict[str, CVEEntry] = {}
        known_exploit_count = 0
        vulnerability_payloads: list[dict[str, Any]] = []

        vulnerability_records: list[dict[str, Any]] = []

        for index, finding in enumerate(findings, 1):
            incident = finding.finding
            diagnostics: dict[str, Any] = {}
            rule_id = self._normalize_rule_id(incident, index, diagnostics)
            remediation_key = rule_id or (incident.contributing_rule_ids[0] if incident.contributing_rule_ids else incident.correlation_id)
            remediation = get_remediation(remediation_key)
            profile = infer_vulnerability_profile(rule_id, incident.severity, cve_id=finding.cve_id, cvss_score=finding.cvss_score)
            if finding.knowledge.get("threat", {}).get("cisa_kev"):
                known_exploit_count += 1

            record = self._validated_vulnerability_record(
                scan_id=scan.id,
                finding_index=index,
                rule_id=rule_id,
                incident=incident,
                finding=finding,
                risk_score=risk.score,
                remediation=remediation,
                profile=profile,
                diagnostics=diagnostics,
            )
            vulnerability_records.append(record)

            vulnerability_payloads.append({
                "rule_id": record["rule_id"],
                "correlation_id": incident.correlation_id,
                "contributing_rule_ids": incident.contributing_rule_ids,
                "title": incident.title,
                "description": record["description"],
                "severity": incident.severity,
                "confidence": incident.confidence,
                "ml_score": risk.score,
                "file_path": record["file_path"],
                "line_number": record["line_number"],
                "remediation": remediation,
                "cve_id": record["cve_id"],
                "cvss_score": finding.cvss_score,
                "cwe_ids": incident.cwe_ids,
                "owasp_category": record["owasp_category"],
                "nist_control": record["nist_control"],
                "mitre_technique": record["mitre_technique"],
                "known_exploit": bool(profile.get("known_exploit")),
                "classification": incident.classification,
                "evidence": incident.evidence,
                "evidence_items": incident.evidence_items,
                "sources": incident.sources,
                "affected_assets": incident.related_assets,
                "limitations": incident.evidence.get("limitations") or incident.evidence.get("errors"),
                "knowledge": finding.knowledge,
                "provider_statuses": finding.knowledge.get("threat", {}).get("provider_statuses", []),
                "graph_context": finding.graph_context,
                "llm_context": finding.llm_context,
                "attack_story": finding.knowledge.get("attack", {}).get("attack_story"),
                "references": finding.references,
            })

            if finding.cve_id and finding.cve_id not in cve_entries:
                cve_entries[finding.cve_id] = CVEEntry(cve_id=finding.cve_id, summary=finding.intelligence[0].summary if finding.intelligence else None, cvss_score=finding.cvss_score, published_date=None, references=finding.references or None)

        for record in vulnerability_records:
            db.add(Vulnerability(**record))

        for entry in cve_entries.values():
            await db.merge(entry)

        cve_details = [{"cve_id": entry.cve_id, "summary": entry.summary, "cvss_score": entry.cvss_score, "published_date": entry.published_date.isoformat() if entry.published_date else None, "references": entry.references or []} for entry in cve_entries.values()]
        compliance_checks = build_compliance_checks(vulnerability_payloads, cve_details)
        for item in compliance_checks:
            db.add(ComplianceCheck(scan_id=scan.id, standard=item["standard"], category=item.get("category"), result=item["result"], score=item.get("score"), details=item.get("details")))

        try:
            await db.commit()
            logger.info("Findings DB commit scan_id=%s vulnerabilities=%s", scan.id, len(vulnerability_records))
        except SQLAlchemyError as exc:
            await db.rollback()
            logger.exception("Failed to persist validated findings for scan %s", scan.id)
            raise ScanPersistenceError(
                "Failed to save scan findings after validation; database rejected the batch"
            ) from exc

        final_verdict = derive_final_audit_verdict(
            overall_score=risk.score,
            compliance_score=self._compliance_score(compliance_checks),
            critical_findings=sum(1 for item in vulnerability_payloads if item["severity"] == "Critical"),
            high_findings=sum(1 for item in vulnerability_payloads if item["severity"] == "High"),
            cve_count=sum(1 for item in vulnerability_payloads if item.get("cve_id")),
            known_exploit_count=known_exploit_count,
        )
        # Generate one deterministic baseline.  The AI review must not render
        # the same filename again: that previously made report contents depend
        # on timing and silently overwrote the first artifact.
        try:
            await asyncio.to_thread(
                build_report,
                scan_id=scan.id,
                target=scan.target,
                scan_type=scan.type,
                overall_score=risk.score,
                vulnerabilities=vulnerability_payloads,
                cve_details=cve_details,
                compliance_checks=compliance_checks,
                audit_verdict=final_verdict,
                ai_insight=None,
                provider_statuses=((scan.result_metadata or {}).get("reputation") or {}).get("provider_statuses") or [],
                started_at=scan.started_at,
                finished_at=datetime.now(timezone.utc),
            )
        except Exception:
            # Findings have already been committed. A document-rendering
            # outage must not turn a completed security scan into a failure.
            logger.exception("Baseline report generation failed scan_id=%s", scan.id)

    async def _queue_ai_review(self, db, scan: Scan) -> None:
        """Queue enrichment after completion without coupling it to scan status."""
        try:
            from app.celery_app import run_ai_review_task

            run_ai_review_task.delay(str(scan.id))
        except Exception as exc:
            logger.exception("Unable to queue AI review scan_id=%s", scan.id)
            try:
                scan.ai_review_status = AIReviewStatus.FAILED.value
                scan.ai_review_error = redact_text(str(exc))[:500] or "Unable to queue AI review"
                await db.commit()
            except Exception:
                await db.rollback()
                logger.exception("Unable to persist AI review queue failure scan_id=%s", scan.id)

    async def run_ai_review(self, scan_id: UUID) -> dict[str, Any]:
        """Generate assisted remediation independently from the completed scan."""
        async with database.async_session_maker() as db:
            scan = await self._load_scan(db, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            if scan.status != ScanStatus.COMPLETED.value:
                return {"scan_id": str(scan_id), "ai_review_status": scan.ai_review_status, "status": scan.status}
            terminal_statuses = {
                AIReviewStatus.COMPLETED.value,
                AIReviewStatus.COMPLETED_AI.value,
                AIReviewStatus.COMPLETED_FALLBACK.value,
                AIReviewStatus.NOT_REQUIRED.value,
                AIReviewStatus.PARTIAL.value,
                AIReviewStatus.TIMED_OUT.value,
            }
            if scan.ai_review_status in terminal_statuses:
                return {"scan_id": str(scan_id), "ai_review_status": scan.ai_review_status, "idempotent": True}

            scan.ai_review_status = AIReviewStatus.PROCESSING.value
            scan.ai_review_error = None
            await db.commit()

            try:
                vulnerabilities_result = await db.execute(
                    select(Vulnerability).where(Vulnerability.scan_id == scan.id).order_by(Vulnerability.created_at.asc())
                )
                vulnerabilities = vulnerabilities_result.scalars().all()
                findings = [
                    {
                        "rule_id": item.rule_id,
                        "description": item.description,
                        "severity": item.severity,
                        "remediation": item.remediation,
                        "cwe_ids": item.cwe_ids or [],
                    }
                    for item in vulnerabilities
                ]
                if not findings:
                    review = await ai_explanation_service.explain_scan(
                        target=scan.target,
                        findings=[],
                        score=scan.overall_score,
                    )
                    metadata = dict(scan.result_metadata or {})
                    metadata["ai_review"] = review
                    metadata["enhanced_report"] = {"status": "not_required"}
                    scan.result_metadata = metadata
                    scan.ai_review_status = AIReviewStatus.NOT_REQUIRED.value
                    scan.ai_review_error = None
                    await db.commit()
                    return {"scan_id": str(scan_id), "ai_review_status": AIReviewStatus.NOT_REQUIRED.value, "review": review}
                review_context = (scan.result_metadata or {}).get("_ai_review_context") or []
                if settings.ENABLE_AI_ENRICHMENT and review_context:
                    enriched_findings = await asyncio.gather(
                        *(
                            knowledge_engine.enrich(
                                CorrelatedFinding.model_validate(item),
                                risk={"score": scan.overall_score or 0},
                            )
                            for item in review_context[: settings.AI_REVIEW_MAX_FINDINGS]
                        )
                    )
                    for vulnerability, enriched_finding in zip(vulnerabilities, enriched_findings):
                        vulnerability.cve_id = enriched_finding.cve_id or vulnerability.cve_id
                        vulnerability.cvss_score = enriched_finding.cvss_score if enriched_finding.cvss_score is not None else vulnerability.cvss_score
                        vulnerability.known_exploit = bool(enriched_finding.kev or vulnerability.known_exploit)
                        vulnerability.references = enriched_finding.references or vulnerability.references
                        vulnerability.ai_explanation = enriched_finding.llm_context or vulnerability.ai_explanation
                review = await ai_explanation_service.explain_scan(
                    target=scan.target,
                    findings=findings,
                    score=scan.overall_score,
                )

                metadata = dict(scan.result_metadata or {})
                metadata["ai_review"] = review
                # The deterministic report remains the single persisted
                # artifact until report versioning/object storage is enabled.
                metadata["enhanced_report"] = {"status": "not_generated"}
                scan.result_metadata = metadata
                review_status = review.get("status", AIReviewStatus.COMPLETED_FALLBACK.value)
                scan.ai_review_status = review_status
                scan.ai_review_error = None
                await db.commit()
                return {"scan_id": str(scan_id), "ai_review_status": review_status, "review": review}
            except Exception as exc:
                await db.rollback()
                logger.exception("AI review failed scan_id=%s", scan_id)
                failed_scan = await self._load_scan(db, scan_id)
                if failed_scan:
                    failed_scan.ai_review_status = AIReviewStatus.FAILED.value
                    failed_scan.ai_review_error = redact_text(str(exc))[:500] or "AI review failed"
                    await db.commit()
                return {"scan_id": str(scan_id), "ai_review_status": AIReviewStatus.FAILED.value}

    def _validated_vulnerability_record(
        self,
        *,
        scan_id: UUID,
        finding_index: int,
        rule_id: str | None,
        incident: CorrelatedFinding,
        finding: EnrichedFinding,
        risk_score: float,
        remediation: str | None,
        profile: dict[str, Any],
        diagnostics: dict[str, Any],
    ) -> dict[str, Any]:
        description = self._clean_text(incident.description, field="description", finding_index=finding_index) or "Security finding"
        severity = self._bounded_string(
            self._map_severity(incident.severity),
            field="severity",
            max_length=BOUNDED_VULNERABILITY_FIELDS["severity"],
            finding_index=finding_index,
            required=True,
        )
        cve_id = self._bounded_string(
            finding.cve_id,
            field="cve_id",
            max_length=BOUNDED_VULNERABILITY_FIELDS["cve_id"],
            finding_index=finding_index,
            identifier=True,
        )
        status = self._bounded_string(
            "open",
            field="status",
            max_length=BOUNDED_VULNERABILITY_FIELDS["status"],
            finding_index=finding_index,
            required=True,
        )
        file_path = self._clean_text(
            incident.evidence.get("file_path") or incident.evidence.get("location") or self._primary_location(incident),
            field="file_path",
            finding_index=finding_index,
        )
        normalized_remediation = self._clean_text(remediation, field="remediation", finding_index=finding_index)
        owasp_category = self._bounded_string(
            profile.get("owasp_category"),
            field="owasp_category",
            max_length=BOUNDED_VULNERABILITY_FIELDS["owasp_category"],
            finding_index=finding_index,
        )
        nist_control = self._bounded_string(
            profile.get("nist_control"),
            field="nist_control",
            max_length=BOUNDED_VULNERABILITY_FIELDS["nist_control"],
            finding_index=finding_index,
        )
        mitre_technique = self._bounded_string(
            profile.get("mitre_technique"),
            field="mitre_technique",
            max_length=BOUNDED_VULNERABILITY_FIELDS["mitre_technique"],
            finding_index=finding_index,
        )
        line_number = self._line_number(incident)
        code_snippet = self._clean_text(incident.evidence.get("line_preview"), field="code_snippet", finding_index=finding_index)
        compliance_results = {
            "owasp_top_10": owasp_category,
            "nist": nist_control,
            "cwe": incident.cwe_ids,
            "intelligence": finding.knowledge.get("compliance", {}),
            "correlation": {
                "correlation_id": incident.correlation_id,
                "contributing_rule_ids": incident.contributing_rule_ids,
            },
        }
        evidence = redact_data({
            **incident.evidence,
            "correlation_id": incident.correlation_id,
            "contributing_rule_ids": incident.contributing_rule_ids,
            "confidence": incident.confidence,
            "confidence_label": incident.evidence.get("confidence_label") or "probable",
            "category": incident.evidence.get("category") or incident.threat_category,
            "title": incident.title,
        })
        if diagnostics:
            compliance_results["diagnostics"] = diagnostics

        bounded_values = {
            "description": description,
            "severity": severity,
            "rule_id": rule_id,
            "cve_id": cve_id,
            "file_path": file_path,
            "remediation": normalized_remediation,
            "status": status,
            "owasp_category": owasp_category,
            "nist_control": nist_control,
            "mitre_technique": mitre_technique,
        }
        self._log_bounded_field_lengths(finding_index, bounded_values)

        return {
            "scan_id": scan_id,
            "rule_id": rule_id,
            "description": description,
            "severity": severity,
            "ml_score": risk_score,
            "file_path": file_path,
            "line_number": line_number,
            "code_snippet": code_snippet,
            "evidence": evidence,
            "remediation": normalized_remediation,
            "cve_id": cve_id,
            "cvss_score": finding.cvss_score,
            "cwe_ids": incident.cwe_ids,
            "owasp_category": owasp_category,
            "nist_control": nist_control,
            "mitre_technique": mitre_technique,
            "known_exploit": bool(profile.get("known_exploit")),
            "references": finding.references or None,
            "status": status,
            "compliance_results": compliance_results,
        }

    def _normalize_rule_id(
        self,
        incident: CorrelatedFinding,
        finding_index: int,
        diagnostics: dict[str, Any],
    ) -> str:
        candidates = self._rule_id_candidates(incident)
        original = candidates[0] if candidates else incident.group_key
        for candidate in candidates:
            value = self._clean_text(candidate, field="rule_id", finding_index=finding_index)
            if value and self._is_valid_rule_id(value):
                if original and value != str(original).strip():
                    diagnostics["rule_id_normalized_from"] = "alternate_contributing_rule_id"
                    diagnostics["original_rule_id_hash"] = self._diagnostic_hash(original)
                    diagnostics["original_rule_id_preview"] = self._diagnostic_preview(original)
                return value

        fallback = self._fallback_rule_id(original or incident.group_key)
        diagnostics["rule_id_normalized_from"] = "malformed_rule_id"
        diagnostics["original_rule_id_hash"] = self._diagnostic_hash(original)
        diagnostics["original_rule_id_preview"] = self._diagnostic_preview(original)
        diagnostics["correlation_id"] = incident.correlation_id
        logger.warning(
            "Replacing malformed rule_id for finding %s with %s; original hash=%s",
            finding_index,
            fallback,
            diagnostics["original_rule_id_hash"],
        )
        return fallback

    def _rule_id_candidates(self, incident: CorrelatedFinding) -> list[Any]:
        candidates: list[Any] = []
        for finding in incident.raw_findings:
            for candidate in (
                finding.raw_data.get("rule_id"),
                finding.evidence.get("rule_id"),
                finding.raw_data.get("source_rule_id"),
                finding.evidence.get("source_rule_id"),
            ):
                if candidate not in candidates:
                    candidates.append(candidate)
        for candidate in incident.contributing_rule_ids:
            if candidate not in candidates:
                candidates.append(candidate)
        return candidates

    def _bounded_string(
        self,
        value: Any,
        *,
        field: str,
        max_length: int,
        finding_index: int,
        required: bool = False,
        identifier: bool = False,
    ) -> str | None:
        cleaned = self._clean_text(value, field=field, finding_index=finding_index)
        if not cleaned:
            if required:
                raise ScanPersistenceError(f"Finding {finding_index} is missing required field {field}")
            return None
        if len(cleaned) <= max_length:
            return cleaned
        if identifier:
            logger.warning(
                "Dropping oversized identifier field %s for finding %s; length=%s max=%s hash=%s",
                field,
                finding_index,
                len(cleaned),
                max_length,
                self._diagnostic_hash(cleaned),
            )
            return None
        logger.warning(
            "Truncating bounded field %s for finding %s; length=%s max=%s hash=%s",
            field,
            finding_index,
            len(cleaned),
            max_length,
            self._diagnostic_hash(cleaned),
        )
        return cleaned[:max_length]

    def _clean_text(self, value: Any, *, field: str, finding_index: int) -> str | None:
        if value is None:
            return None
        if isinstance(value, (str, int, float, bool)):
            cleaned = str(value).strip()
        else:
            cleaned = str(value).strip()
        if not cleaned:
            return None
        return cleaned

    def _is_valid_rule_id(self, value: str) -> bool:
        return bool(RULE_ID_PATTERN.fullmatch(value)) and len(value) <= BOUNDED_VULNERABILITY_FIELDS["rule_id"]

    def _fallback_rule_id(self, value: Any) -> str:
        digest = self._diagnostic_hash(value)[:12].upper()
        return f"VN-FALLBACK-{digest}"

    def _diagnostic_hash(self, value: Any) -> str:
        return hashlib.sha256(str(value or "").encode("utf-8", errors="ignore")).hexdigest()

    def _diagnostic_preview(self, value: Any) -> str:
        return redact_text(str(value or ""))[:160]

    def _primary_location(self, incident: CorrelatedFinding) -> str | None:
        if incident.raw_findings:
            return incident.raw_findings[0].location
        locations = incident.evidence.get("locations")
        if isinstance(locations, list) and locations:
            return str(locations[0])
        return None

    def _line_number(self, incident: CorrelatedFinding) -> int | None:
        value = incident.evidence.get("line_number")
        if value is None and incident.raw_findings:
            value = incident.raw_findings[0].evidence.get("line_number")
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def _log_bounded_field_lengths(self, finding_index: int, fields: dict[str, Any]) -> None:
        if settings.ENVIRONMENT not in {"development", "dev", "test", "testing"}:
            return
        lengths = {field: len(str(value)) for field, value in fields.items() if value is not None}
        over_limit = {
            field: length
            for field, length in lengths.items()
            if field in BOUNDED_VULNERABILITY_FIELDS and length > BOUNDED_VULNERABILITY_FIELDS[field]
        }
        logger.debug(
            "Validated vulnerability bounded field lengths for finding %s: lengths=%s over_limit=%s",
            finding_index,
            lengths,
            over_limit,
        )

    def _persistence_error_message(self, exc: Exception) -> str:
        if isinstance(exc, ScanPersistenceError):
            return redact_text(str(exc))[:500]
        if isinstance(exc, SQLAlchemyError):
            return "Failed to save scan findings because the database rejected the validated batch"
        return redact_text(str(exc))[:500] or "Failed to save scan findings"

    async def _load_scan(self, db, scan_id: UUID):
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        return result.scalar_one_or_none()

    async def _raise_if_canceled(self, scan_id: UUID) -> None:
        async with database.async_session_maker() as db:
            scan = await self._load_scan(db, scan_id)
            if scan and scan.status == ScanStatus.CANCELED.value:
                raise RuntimeError("Scan canceled by user")

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
        logger.info("Scan DB commit scan_id=%s status=%s", scan.id, scan.status)

    async def _store_progress(self, context: ScanContext, **updates) -> None:
        progress = ScanProgress(scan_id=context.scan_id, status=updates.get("status", "queued"), progress=updates.get("progress", context.progress), stage=updates.get("stage", context.stage), message=updates.get("message"), started_at=updates.get("started_at"), finished_at=updates.get("finished_at"), error_message=updates.get("error_message"), details=updates.get("details", {}))
        payload = progress.model_dump(mode="json")
        await cache.set("scan_progress", str(context.scan_id), payload)
        try:
            from app.routes.scan_routes import manager
            await manager.broadcast_status(str(context.scan_id), payload)
        except Exception:
            pass

    def _map_severity(self, severity: str) -> str:
        mapping = {"Info": Severity.LOW.value, "Low": Severity.LOW.value, "Medium": Severity.MEDIUM.value, "High": Severity.HIGH.value, "Critical": Severity.CRITICAL.value}
        return mapping.get(severity, Severity.MEDIUM.value)

    def _compliance_score(self, compliance_checks: list[dict[str, Any]]) -> float | None:
        if not compliance_checks:
            return None
        passed = sum(1 for item in compliance_checks if item["result"] == "pass")
        return round((passed / len(compliance_checks)) * 100, 2)


scan_orchestrator = ScanOrchestrator()
