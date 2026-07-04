import os
import uuid
import asyncio
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import database
from app.models.db_models import Scan, ScanFile, Vulnerability, CVEEntry, ComplianceCheck, MLFeature, ScanStatus, Severity
from app.models.pydantic_models import CryptoFeatures, RuleVulnerability
from app.services.file_scanner import scan_files
from app.services.web_scanner import scan_url
from app.services.rule_engine import evaluate_rules
from app.services.ai_risk_model import AIRiskModel
from app.services.cve_mapper import map_vulnerability_to_cves
from app.services.intelligence.service import map_finding_intelligence
from app.services.report_generator import build_report, get_remediation
from app.services.audit_engine import build_ai_insight, build_compliance_checks, derive_final_audit_verdict, infer_vulnerability_profile
from app.services.github_repo_scanner import materialize_repository_source
from app.utils.file_utils import extract_zip
from app.utils.crypto import decrypt_token
from app.utils.logger import get_logger, timed_stage
from app.config import settings

logger = get_logger(__name__)
ai_model = AIRiskModel()


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(normalized)
        except ValueError:
            return None
    return None


async def run_file_scan(scan_id: uuid.UUID, file_path: str):
    async with database.async_session_maker() as db:
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                return

            scan.started_at = datetime.utcnow()
            await _update_scan(db, scan_id, status=ScanStatus.IN_PROGRESS.value, started_at=scan.started_at, progress=5)

            with timed_stage(logger, "file_extraction"):
                if file_path.endswith(".zip"):
                    import os
                    extract_dir = os.path.join(settings.UPLOAD_DIR, str(scan_id), "extracted")
                    os.makedirs(extract_dir, exist_ok=True)
                    extracted = extract_zip(file_path, extract_dir)
                    source_files = extracted
                else:
                    source_files = [file_path]

            await _update_scan(db, scan_id, progress=20)

            if source_files:
                for sf in source_files:
                    db.add(ScanFile(
                        scan_id=scan_id,
                        filename=sf.split("/")[-1].split("\\")[-1],
                        path=sf,
                    ))
                await db.commit()

            with timed_stage(logger, "static_code_scan"):
                file_vulns, file_features = await asyncio.to_thread(scan_files, source_files)

            await _update_scan(db, scan_id, progress=40)

            with timed_stage(logger, "rule_engine"):
                rule_vulns, rule_score = await asyncio.to_thread(evaluate_rules, file_features)

            await _update_scan(db, scan_id, progress=55)

            merged_features = _merge_features(file_features)
            merged_features.rule_score = rule_score

            with timed_stage(logger, "ai_scoring"):
                prediction = ai_model.predict(merged_features)

            await _update_scan(db, scan_id, progress=70)

            all_vulns = _deduplicate_vulns(file_vulns + rule_vulns)

            with timed_stage(logger, "cve_mapping"):
                cve_details, keyword_to_cve = await _map_cves_for_vulns(db, all_vulns)

            cve_detail_map = {entry.get("cve_id"): entry for entry in cve_details if entry.get("cve_id")}

            for entry in cve_details:
                if not entry.get("cve_id"):
                    continue
                await db.merge(CVEEntry(
                    cve_id=entry["cve_id"],
                    summary=entry.get("summary"),
                    cvss_score=entry.get("cvss_score"),
                    published_date=_parse_datetime(entry.get("published_date")),
                    severity=entry.get("severity"),
                ))

            await _update_scan(db, scan_id, progress=85)

            vuln_dicts = []
            known_exploit_count = 0
            for v in all_vulns:
                remediation = get_remediation(v.rule_id) if v.rule_id else None
                keyword = v.crypto_feature or v.rule_id
                cve_id = keyword_to_cve.get(keyword) if keyword else None
                cve_entry = cve_detail_map.get(cve_id) if cve_id else None
                profile = infer_vulnerability_profile(v.rule_id, v.severity, cve_id=cve_id, cvss_score=(cve_entry or {}).get("cvss_score"))
                if profile.get("known_exploit"):
                    known_exploit_count += 1
                vuln = Vulnerability(
                    scan_id=scan_id,
                    rule_id=v.rule_id,
                    description=v.description,
                    severity=_map_severity(v.severity),
                    ml_score=prediction.score,
                    file_path=v.file_path,
                    line_number=v.line_number,
                    remediation=remediation,
                    cve_id=cve_id,
                    cvss_score=(cve_entry or {}).get("cvss_score"),
                    cwe_ids=profile.get("cwe_ids"),
                    owasp_category=profile.get("owasp_category"),
                    nist_control=profile.get("nist_control"),
                    mitre_technique=profile.get("mitre_technique"),
                    known_exploit=bool(profile.get("known_exploit")),
                    references=(cve_entry or {}).get("references") or ([f"https://nvd.nist.gov/vuln/detail/{cve_id}"] if cve_id else None),
                    compliance_results={
                        "owasp_top_10": profile.get("owasp_category"),
                        "nist": profile.get("nist_control"),
                        "cwe": profile.get("cwe_ids"),
                    },
                )
                db.add(vuln)
                vuln_dicts.append({
                    "rule_id": v.rule_id,
                    "description": v.description,
                    "severity": v.severity,
                    "ml_score": prediction.score,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "remediation": remediation,
                    "cve_id": cve_id,
                    "cvss_score": (cve_entry or {}).get("cvss_score"),
                    "cwe_ids": profile.get("cwe_ids"),
                    "owasp_category": profile.get("owasp_category"),
                    "nist_control": profile.get("nist_control"),
                    "mitre_technique": profile.get("mitre_technique"),
                    "known_exploit": bool(profile.get("known_exploit")),
                })

            compliance_checks = build_compliance_checks(vuln_dicts, cve_details)

            for check in compliance_checks:
                db.add(ComplianceCheck(
                    scan_id=scan_id,
                    standard=check["standard"],
                    category=check.get("category"),
                    result=check["result"],
                    score=check.get("score"),
                    details=check.get("details"),
                ))

            db.add(MLFeature(
                scan_id=scan_id,
                features_json=merged_features.model_dump(),
                label=prediction.severity,
            ))
            await db.commit()

            finished_at = datetime.utcnow()
            compliance_score = None
            if compliance_checks:
                compliance_score = round((sum(1 for item in compliance_checks if item["result"] == "pass") / len(compliance_checks)) * 100, 2)

            verdict = derive_final_audit_verdict(
                overall_score=prediction.score,
                compliance_score=compliance_score,
                critical_findings=sum(1 for item in vuln_dicts if item["severity"] == "Critical"),
                high_findings=sum(1 for item in vuln_dicts if item["severity"] == "High"),
                cve_count=sum(1 for item in vuln_dicts if item.get("cve_id")),
                known_exploit_count=known_exploit_count,
            )
            ai_insight = build_ai_insight(
                target=scan.target,
                scan_type="file",
                overall_score=prediction.score,
                compliance_score=compliance_score,
                verdict=verdict,
                vulnerabilities=vuln_dicts,
            )
            with timed_stage(logger, "report_generation"):
                await asyncio.to_thread(
                    build_report,
                    scan_id=scan_id,
                    target=scan.target,
                    scan_type="file",
                    overall_score=prediction.score,
                    vulnerabilities=vuln_dicts,
                    cve_details=cve_details,
                    compliance_checks=compliance_checks,
                    audit_verdict=verdict,
                    ai_insight=ai_insight,
                    started_at=scan.started_at,
                    finished_at=finished_at,
                )

            await _update_scan(
                db, scan_id,
                overall_score=prediction.score,
                status=ScanStatus.COMPLETED.value,
                finished_at=finished_at,
                progress=100,
            )
            logger.info(f"File scan {scan_id} completed with score {prediction.score}")

        except Exception as e:
            logger.error(f"File scan {scan_id} failed: {e}")
            await _update_scan(
                db, scan_id,
                status=ScanStatus.FAILED.value,
                error_message=str(e)[:500],
                finished_at=datetime.utcnow(),
            )


async def run_url_scan(scan_id: uuid.UUID, target_url: str):
    async with database.async_session_maker() as db:
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                return

            scan.started_at = datetime.utcnow()
            await _update_scan(db, scan_id, status=ScanStatus.IN_PROGRESS.value, started_at=scan.started_at, progress=5)

            with timed_stage(logger, "tls_scan"):
                web_vulns, web_features = await scan_url(target_url)

            await _update_scan(db, scan_id, progress=30)

            with timed_stage(logger, "rule_engine"):
                rule_vulns, rule_score = await asyncio.to_thread(evaluate_rules, [web_features])

            await _update_scan(db, scan_id, progress=50)

            web_features.rule_score = rule_score

            with timed_stage(logger, "ai_scoring"):
                prediction = ai_model.predict(web_features)

            await _update_scan(db, scan_id, progress=65)

            all_vulns = _deduplicate_vulns(web_vulns + rule_vulns)

            with timed_stage(logger, "cve_mapping"):
                cve_details, keyword_to_cve = await _map_cves_for_vulns(db, all_vulns)

            cve_detail_map = {entry.get("cve_id"): entry for entry in cve_details if entry.get("cve_id")}

            for entry in cve_details:
                if not entry.get("cve_id"):
                    continue
                await db.merge(CVEEntry(
                    cve_id=entry["cve_id"],
                    summary=entry.get("summary"),
                    cvss_score=entry.get("cvss_score"),
                    published_date=_parse_datetime(entry.get("published_date")),
                    severity=entry.get("severity"),
                ))

            await _update_scan(db, scan_id, progress=80)

            vuln_dicts = []
            known_exploit_count = 0
            for v in all_vulns:
                remediation = get_remediation(v.rule_id) if v.rule_id else None
                keyword = v.crypto_feature or v.rule_id
                cve_id = keyword_to_cve.get(keyword) if keyword else None
                cve_entry = cve_detail_map.get(cve_id) if cve_id else None
                profile = infer_vulnerability_profile(v.rule_id, v.severity, cve_id=cve_id, cvss_score=(cve_entry or {}).get("cvss_score"))
                if profile.get("known_exploit"):
                    known_exploit_count += 1
                vuln = Vulnerability(
                    scan_id=scan_id,
                    rule_id=v.rule_id,
                    description=v.description,
                    severity=_map_severity(v.severity),
                    ml_score=prediction.score,
                    remediation=remediation,
                    cve_id=cve_id,
                    cvss_score=(cve_entry or {}).get("cvss_score"),
                    cwe_ids=profile.get("cwe_ids"),
                    owasp_category=profile.get("owasp_category"),
                    nist_control=profile.get("nist_control"),
                    mitre_technique=profile.get("mitre_technique"),
                    known_exploit=bool(profile.get("known_exploit")),
                    references=(cve_entry or {}).get("references") or ([f"https://nvd.nist.gov/vuln/detail/{cve_id}"] if cve_id else None),
                    compliance_results={
                        "owasp_top_10": profile.get("owasp_category"),
                        "nist": profile.get("nist_control"),
                        "cwe": profile.get("cwe_ids"),
                    },
                )
                db.add(vuln)
                vuln_dicts.append({
                    "rule_id": v.rule_id,
                    "description": v.description,
                    "severity": v.severity,
                    "ml_score": prediction.score,
                    "remediation": remediation,
                    "cve_id": cve_id,
                    "cvss_score": (cve_entry or {}).get("cvss_score"),
                    "file_path": None,
                    "line_number": None,
                    "cwe_ids": profile.get("cwe_ids"),
                    "owasp_category": profile.get("owasp_category"),
                    "nist_control": profile.get("nist_control"),
                    "mitre_technique": profile.get("mitre_technique"),
                    "known_exploit": bool(profile.get("known_exploit")),
                })

            compliance_checks = build_compliance_checks(vuln_dicts, cve_details)

            for check in compliance_checks:
                db.add(ComplianceCheck(
                    scan_id=scan_id,
                    standard=check["standard"],
                    category=check.get("category"),
                    result=check["result"],
                    score=check.get("score"),
                    details=check.get("details"),
                ))

            db.add(MLFeature(
                scan_id=scan_id,
                features_json=web_features.model_dump(),
                label=prediction.severity,
            ))
            await db.commit()

            finished_at = datetime.utcnow()
            compliance_score = None
            if compliance_checks:
                compliance_score = round((sum(1 for item in compliance_checks if item["result"] == "pass") / len(compliance_checks)) * 100, 2)

            verdict = derive_final_audit_verdict(
                overall_score=prediction.score,
                compliance_score=compliance_score,
                critical_findings=sum(1 for item in vuln_dicts if item["severity"] == "Critical"),
                high_findings=sum(1 for item in vuln_dicts if item["severity"] == "High"),
                cve_count=sum(1 for item in vuln_dicts if item.get("cve_id")),
                known_exploit_count=known_exploit_count,
            )
            ai_insight = build_ai_insight(
                target=target_url,
                scan_type="url",
                overall_score=prediction.score,
                compliance_score=compliance_score,
                verdict=verdict,
                vulnerabilities=vuln_dicts,
            )
            with timed_stage(logger, "report_generation"):
                await asyncio.to_thread(
                    build_report,
                    scan_id=scan_id,
                    target=target_url,
                    scan_type="url",
                    overall_score=prediction.score,
                    vulnerabilities=vuln_dicts,
                    cve_details=cve_details,
                    compliance_checks=compliance_checks,
                    audit_verdict=verdict,
                    ai_insight=ai_insight,
                    started_at=scan.started_at,
                    finished_at=finished_at,
                )

            await _update_scan(
                db, scan_id,
                overall_score=prediction.score,
                status=ScanStatus.COMPLETED.value,
                finished_at=finished_at,
                progress=100,
            )
            logger.info(f"URL scan {scan_id} completed with score {prediction.score}")

        except Exception as e:
            logger.error(f"URL scan {scan_id} failed: {e}")
            await _update_scan(
                db, scan_id,
                status=ScanStatus.FAILED.value,
                error_message=str(e)[:500],
                finished_at=datetime.utcnow(),
            )


async def run_github_repo_scan(scan_id: uuid.UUID, user_id: uuid.UUID, owner: str, repository: str, branch: str, folder: str = ""):
    async with database.async_session_maker() as db:
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                return

            scan.started_at = datetime.utcnow()
            scan.github_org = owner
            scan.github_repo = repository
            scan.github_branch = branch
            scan.github_folder = folder or None
            await _update_scan(db, scan_id, status=ScanStatus.IN_PROGRESS.value, started_at=scan.started_at, progress=5)

            from app.models.db_models import GitHubConnection

            connection_result = await db.execute(select(GitHubConnection).where(GitHubConnection.user_id == user_id))
            connection = connection_result.scalar_one_or_none()
            if not connection or not connection.is_connected:
                raise ValueError("GitHub account is not connected")

            access_token = await decrypt_token(connection.access_token)

            with timed_stage(logger, "repo_materialization"):
                scan_dir = os.path.join(settings.UPLOAD_DIR, str(scan_id), "repository")
                os.makedirs(scan_dir, exist_ok=True)
                source_files = await materialize_repository_source(
                    access_token=access_token,
                    owner=owner,
                    repository=repository,
                    branch=branch,
                    destination_dir=scan_dir,
                    folder=folder or "",
                )

            await _update_scan(db, scan_id, progress=20)

            if source_files:
                for sf in source_files:
                    db.add(ScanFile(
                        scan_id=scan_id,
                        filename=sf.split("/")[-1].split("\\")[-1],
                        path=sf,
                    ))
                await db.commit()

            with timed_stage(logger, "static_code_scan"):
                file_vulns, file_features = await asyncio.to_thread(scan_files, source_files)

            await _update_scan(db, scan_id, progress=40)

            with timed_stage(logger, "rule_engine"):
                rule_vulns, rule_score = await asyncio.to_thread(evaluate_rules, file_features)

            await _update_scan(db, scan_id, progress=55)

            merged_features = _merge_features(file_features)
            merged_features.rule_score = rule_score

            with timed_stage(logger, "ai_scoring"):
                prediction = ai_model.predict(merged_features)

            await _update_scan(db, scan_id, progress=70)

            all_vulns = _deduplicate_vulns(file_vulns + rule_vulns)

            with timed_stage(logger, "cve_mapping"):
                cve_details, keyword_to_cve = await _map_cves_for_vulns(db, all_vulns)

            cve_detail_map = {entry.get("cve_id"): entry for entry in cve_details if entry.get("cve_id")}

            for entry in cve_details:
                if not entry.get("cve_id"):
                    continue
                await db.merge(CVEEntry(
                    cve_id=entry["cve_id"],
                    summary=entry.get("summary"),
                    cvss_score=entry.get("cvss_score"),
                    published_date=_parse_datetime(entry.get("published_date")),
                    severity=entry.get("severity"),
                ))

            await _update_scan(db, scan_id, progress=85)

            vuln_dicts = []
            known_exploit_count = 0
            for v in all_vulns:
                remediation = get_remediation(v.rule_id) if v.rule_id else None
                keyword = v.crypto_feature or v.rule_id
                cve_id = keyword_to_cve.get(keyword) if keyword else None
                cve_entry = cve_detail_map.get(cve_id) if cve_id else None
                profile = infer_vulnerability_profile(v.rule_id, v.severity, cve_id=cve_id, cvss_score=(cve_entry or {}).get("cvss_score"))
                if profile.get("known_exploit"):
                    known_exploit_count += 1
                vuln = Vulnerability(
                    scan_id=scan_id,
                    rule_id=v.rule_id,
                    description=v.description,
                    severity=_map_severity(v.severity),
                    ml_score=prediction.score,
                    file_path=v.file_path,
                    line_number=v.line_number,
                    remediation=remediation,
                    cve_id=cve_id,
                    cvss_score=(cve_entry or {}).get("cvss_score"),
                    cwe_ids=profile.get("cwe_ids"),
                    owasp_category=profile.get("owasp_category"),
                    nist_control=profile.get("nist_control"),
                    mitre_technique=profile.get("mitre_technique"),
                    known_exploit=bool(profile.get("known_exploit")),
                    references=(cve_entry or {}).get("references") or ([f"https://nvd.nist.gov/vuln/detail/{cve_id}"] if cve_id else None),
                    compliance_results={
                        "owasp_top_10": profile.get("owasp_category"),
                        "nist": profile.get("nist_control"),
                        "cwe": profile.get("cwe_ids"),
                    },
                )
                db.add(vuln)
                vuln_dicts.append({
                    "rule_id": v.rule_id,
                    "description": v.description,
                    "severity": v.severity,
                    "ml_score": prediction.score,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "remediation": remediation,
                    "cve_id": cve_id,
                    "cvss_score": (cve_entry or {}).get("cvss_score"),
                    "cwe_ids": profile.get("cwe_ids"),
                    "owasp_category": profile.get("owasp_category"),
                    "nist_control": profile.get("nist_control"),
                    "mitre_technique": profile.get("mitre_technique"),
                    "known_exploit": bool(profile.get("known_exploit")),
                })

            compliance_checks = build_compliance_checks(vuln_dicts, cve_details)

            for check in compliance_checks:
                db.add(ComplianceCheck(
                    scan_id=scan_id,
                    standard=check["standard"],
                    category=check.get("category"),
                    result=check["result"],
                    score=check.get("score"),
                    details=check.get("details"),
                ))

            db.add(MLFeature(
                scan_id=scan_id,
                features_json=merged_features.model_dump(),
                label=prediction.severity,
            ))
            await db.commit()

            finished_at = datetime.utcnow()
            compliance_score = None
            if compliance_checks:
                compliance_score = round((sum(1 for item in compliance_checks if item["result"] == "pass") / len(compliance_checks)) * 100, 2)

            verdict = derive_final_audit_verdict(
                overall_score=prediction.score,
                compliance_score=compliance_score,
                critical_findings=sum(1 for item in vuln_dicts if item["severity"] == "Critical"),
                high_findings=sum(1 for item in vuln_dicts if item["severity"] == "High"),
                cve_count=sum(1 for item in vuln_dicts if item.get("cve_id")),
                known_exploit_count=known_exploit_count,
            )
            ai_insight = build_ai_insight(
                target=f"{owner}/{repository}",
                scan_type="github",
                overall_score=prediction.score,
                compliance_score=compliance_score,
                verdict=verdict,
                vulnerabilities=vuln_dicts,
            )
            with timed_stage(logger, "report_generation"):
                await asyncio.to_thread(
                    build_report,
                    scan_id=scan_id,
                    target=f"{owner}/{repository}",
                    scan_type="github",
                    overall_score=prediction.score,
                    vulnerabilities=vuln_dicts,
                    cve_details=cve_details,
                    compliance_checks=compliance_checks,
                    audit_verdict=verdict,
                    ai_insight=ai_insight,
                    started_at=scan.started_at,
                    finished_at=finished_at,
                )

            await _update_scan(
                db, scan_id,
                overall_score=prediction.score,
                status=ScanStatus.COMPLETED.value,
                finished_at=finished_at,
                progress=100,
            )
            logger.info(f"GitHub repository scan {scan_id} completed with score {prediction.score}")

        except Exception as e:
            logger.error(f"GitHub repository scan {scan_id} failed: {e}")
            await _update_scan(
                db, scan_id,
                status=ScanStatus.FAILED.value,
                error_message=str(e)[:500],
                finished_at=datetime.utcnow(),
            )


def _merge_features(features_list: list[CryptoFeatures]) -> CryptoFeatures:
    if not features_list:
        return CryptoFeatures()
    merged = CryptoFeatures()
    for f in features_list:
        if f.key_size and (merged.key_size is None or f.key_size < merged.key_size):
            merged.key_size = f.key_size
        merged.uses_md5 = merged.uses_md5 or f.uses_md5
        merged.uses_sha1 = merged.uses_sha1 or f.uses_sha1
        merged.uses_des = merged.uses_des or f.uses_des
        merged.uses_rc2 = merged.uses_rc2 or f.uses_rc2
        merged.uses_ecb = merged.uses_ecb or f.uses_ecb
        merged.rsa_key_small = merged.rsa_key_small or f.rsa_key_small
        merged.aes_key_small = merged.aes_key_small or f.aes_key_small
        merged.hardcoded_key = merged.hardcoded_key or f.hardcoded_key
        merged.insecure_random = merged.insecure_random or f.insecure_random
        if f.tls_version and f.tls_version != "unknown":
            merged.tls_version = f.tls_version
        if f.cert_valid_days:
            merged.cert_valid_days = f.cert_valid_days
        if f.forward_secrecy is not None:
            merged.forward_secrecy = f.forward_secrecy
        if f.has_hsts is not None:
            merged.has_hsts = f.has_hsts
        if f.self_signed is not None:
            merged.self_signed = f.self_signed
    return merged


def _deduplicate_vulns(vulns: list[RuleVulnerability]) -> list[RuleVulnerability]:
    seen = set()
    unique = []
    for v in vulns:
        key = (v.rule_id, v.file_path, v.line_number)
        if key not in seen:
            seen.add(key)
            unique.append(v)
    return unique


def _map_severity(sev_str: str) -> str:
    mapping = {
        "Low": Severity.LOW.value,
        "Medium": Severity.MEDIUM.value,
        "High": Severity.HIGH.value,
        "Critical": Severity.CRITICAL.value,
    }
    return mapping.get(sev_str, Severity.MEDIUM.value)


async def _map_cves_for_vulns(db: AsyncSession, vulns: list[RuleVulnerability]) -> tuple[list[dict], dict[str, str]]:
    keyword_vulns: dict[str, RuleVulnerability] = {}
    for vuln in vulns:
        keyword = vuln.crypto_feature or vuln.rule_id
        if keyword and keyword not in keyword_vulns:
            keyword_vulns[keyword] = vuln

    mapped_results = await asyncio.gather(
        *(
            map_finding_intelligence(
                keyword,
                rule_id=vuln.rule_id,
                severity=vuln.severity,
                description=vuln.description,
                metadata=vuln.model_dump(),
            )
            for keyword, vuln in keyword_vulns.items()
        ),
        return_exceptions=True,
    )

    all_cves: list[dict] = []
    seen_cve_ids: set[str] = set()
    keyword_to_cve: dict[str, str] = {}

    for (keyword, _vuln), mapped in zip(keyword_vulns.items(), mapped_results):
        if isinstance(mapped, Exception):
            logger.debug("Intelligence mapping failed for %s: %s", keyword, mapped)
            continue

        if mapped.requires_cve_lookup and mapped.cve_id:
            keyword_to_cve[keyword] = mapped.cve_id

        for cve in mapped.provider_hits:
            cve_id = cve.get("identifier")
            if not cve_id:
                continue
            if keyword not in keyword_to_cve:
                keyword_to_cve[keyword] = cve_id
            normalized = {
                "cve_id": cve_id,
                "summary": cve.get("summary"),
                "cvss_score": cve.get("cvss_score"),
                "published_date": cve.get("published_date"),
                "source": cve.get("source"),
                "references": cve.get("references") or [],
            }
            if cve_id not in seen_cve_ids:
                seen_cve_ids.add(cve_id)
                all_cves.append(normalized)
                existing = await db.execute(select(CVEEntry).where(CVEEntry.cve_id == cve_id))
                if not existing.scalar_one_or_none():
                    db.add(CVEEntry(
                        cve_id=cve_id,
                        summary=normalized.get("summary"),
                        cvss_score=normalized.get("cvss_score"),
                        published_date=None,
                        references=normalized.get("references"),
                    ))
    await db.commit()
    return all_cves, keyword_to_cve


async def _update_scan(db: AsyncSession, scan_id: uuid.UUID, **updates) -> None:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        return
    for key, value in updates.items():
        if value is not None:
            setattr(scan, key, value)
    await db.commit()
