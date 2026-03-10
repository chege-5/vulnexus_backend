import uuid
import asyncio
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.db_models import Scan, ScanFile, Vulnerability, CVEEntry, MLFeature, ScanStatus, ScanType, Severity
from app.models.pydantic_models import CryptoFeatures, RuleVulnerability
from app.services.file_scanner import scan_files
from app.services.web_scanner import scan_url
from app.services.rule_engine import evaluate_rules
from app.services.ai_risk_model import AIRiskModel
from app.services.cve_mapper import map_vulnerability_to_cves
from app.services.report_generator import build_report, get_remediation
from app.utils.file_utils import extract_zip
from app.utils.logger import get_logger, timed_stage
from app.config import settings
from app.deps import async_session_factory

logger = get_logger(__name__)
ai_model = AIRiskModel()


async def run_file_scan(scan_id: uuid.UUID, file_path: str):
    async with async_session_factory() as db:
        try:
            scan = await db.get(Scan, scan_id)
            if not scan:
                return
            scan.status = ScanStatus.IN_PROGRESS
            scan.started_at = datetime.utcnow()
            scan.progress = 5
            await db.commit()

            with timed_stage(logger, "file_extraction"):
                if file_path.endswith(".zip"):
                    import os
                    extract_dir = os.path.join(settings.UPLOAD_DIR, str(scan_id), "extracted")
                    os.makedirs(extract_dir, exist_ok=True)
                    extracted = extract_zip(file_path, extract_dir)
                    source_files = extracted
                else:
                    source_files = [file_path]

            scan.progress = 20
            await db.commit()

            for sf in source_files:
                db_file = ScanFile(scan_id=scan_id, filename=sf.split("/")[-1].split("\\")[-1], path=sf)
                db.add(db_file)
            await db.commit()

            with timed_stage(logger, "static_code_scan"):
                file_vulns, file_features = await asyncio.to_thread(scan_files, source_files)

            scan.progress = 40
            await db.commit()

            with timed_stage(logger, "rule_engine"):
                rule_vulns, rule_score = await asyncio.to_thread(evaluate_rules, file_features)

            scan.progress = 55
            await db.commit()

            merged_features = _merge_features(file_features)
            merged_features.rule_score = rule_score

            with timed_stage(logger, "ai_scoring"):
                prediction = ai_model.predict(merged_features)

            scan.progress = 70
            await db.commit()

            all_vulns = _deduplicate_vulns(file_vulns + rule_vulns)

            with timed_stage(logger, "cve_mapping"):
                cve_details, keyword_to_cve = await _map_cves_for_vulns(all_vulns, db)

            scan.progress = 85
            await db.commit()

            vuln_dicts = []
            for v in all_vulns:
                remediation = get_remediation(v.rule_id) if v.rule_id else None
                keyword = v.crypto_feature or v.rule_id
                cve_id = keyword_to_cve.get(keyword) if keyword else None
                db_vuln = Vulnerability(
                    scan_id=scan_id,
                    rule_id=v.rule_id,
                    description=v.description,
                    severity=_map_severity(v.severity),
                    ml_score=prediction.score,
                    file_path=v.file_path,
                    line_number=v.line_number,
                    remediation=remediation,
                    cve_id=cve_id,
                )
                db.add(db_vuln)
                vuln_dicts.append({
                    "rule_id": v.rule_id,
                    "description": v.description,
                    "severity": v.severity,
                    "ml_score": prediction.score,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "remediation": remediation,
                    "cve_id": cve_id,
                })

            ml_feat = MLFeature(
                scan_id=scan_id,
                features_json=merged_features.model_dump(),
                label=prediction.severity,
            )
            db.add(ml_feat)

            with timed_stage(logger, "report_generation"):
                await asyncio.to_thread(
                    build_report,
                    scan_id=scan_id,
                    target=scan.target,
                    scan_type="file",
                    overall_score=prediction.score,
                    vulnerabilities=vuln_dicts,
                    cve_details=cve_details,
                    started_at=scan.started_at,
                    finished_at=datetime.utcnow(),
                )

            scan.overall_score = prediction.score
            scan.status = ScanStatus.COMPLETED
            scan.finished_at = datetime.utcnow()
            scan.progress = 100
            await db.commit()
            logger.info(f"File scan {scan_id} completed with score {prediction.score}")

        except Exception as e:
            logger.error(f"File scan {scan_id} failed: {e}")
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)[:500]
                scan.finished_at = datetime.utcnow()
                await db.commit()


async def run_url_scan(scan_id: uuid.UUID, target_url: str):
    async with async_session_factory() as db:
        try:
            scan = await db.get(Scan, scan_id)
            if not scan:
                return
            scan.status = ScanStatus.IN_PROGRESS
            scan.started_at = datetime.utcnow()
            scan.progress = 5
            await db.commit()

            with timed_stage(logger, "tls_scan"):
                web_vulns, web_features = await scan_url(target_url)

            scan.progress = 30
            await db.commit()

            with timed_stage(logger, "rule_engine"):
                rule_vulns, rule_score = await asyncio.to_thread(evaluate_rules, [web_features])

            scan.progress = 50
            await db.commit()

            web_features.rule_score = rule_score

            with timed_stage(logger, "ai_scoring"):
                prediction = ai_model.predict(web_features)

            scan.progress = 65
            await db.commit()

            all_vulns = _deduplicate_vulns(web_vulns + rule_vulns)

            with timed_stage(logger, "cve_mapping"):
                cve_details, keyword_to_cve = await _map_cves_for_vulns(all_vulns, db)

            scan.progress = 80
            await db.commit()

            vuln_dicts = []
            for v in all_vulns:
                remediation = get_remediation(v.rule_id) if v.rule_id else None
                keyword = v.crypto_feature or v.rule_id
                cve_id = keyword_to_cve.get(keyword) if keyword else None
                db_vuln = Vulnerability(
                    scan_id=scan_id,
                    rule_id=v.rule_id,
                    description=v.description,
                    severity=_map_severity(v.severity),
                    ml_score=prediction.score,
                    remediation=remediation,
                    cve_id=cve_id,
                )
                db.add(db_vuln)
                vuln_dicts.append({
                    "rule_id": v.rule_id,
                    "description": v.description,
                    "severity": v.severity,
                    "ml_score": prediction.score,
                    "remediation": remediation,
                    "cve_id": cve_id,
                    "file_path": None,
                    "line_number": None,
                })

            ml_feat = MLFeature(
                scan_id=scan_id,
                features_json=web_features.model_dump(),
                label=prediction.severity,
            )
            db.add(ml_feat)

            with timed_stage(logger, "report_generation"):
                await asyncio.to_thread(
                    build_report,
                    scan_id=scan_id,
                    target=target_url,
                    scan_type="url",
                    overall_score=prediction.score,
                    vulnerabilities=vuln_dicts,
                    cve_details=cve_details,
                    started_at=scan.started_at,
                    finished_at=datetime.utcnow(),
                )

            scan.overall_score = prediction.score
            scan.status = ScanStatus.COMPLETED
            scan.finished_at = datetime.utcnow()
            scan.progress = 100
            await db.commit()
            logger.info(f"URL scan {scan_id} completed with score {prediction.score}")

        except Exception as e:
            logger.error(f"URL scan {scan_id} failed: {e}")
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)[:500]
                scan.finished_at = datetime.utcnow()
                await db.commit()


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


def _map_severity(sev_str: str) -> Severity:
    mapping = {
        "Low": Severity.LOW,
        "Medium": Severity.MEDIUM,
        "High": Severity.HIGH,
        "Critical": Severity.CRITICAL,
    }
    return mapping.get(sev_str, Severity.MEDIUM)


async def _map_cves_for_vulns(vulns: list[RuleVulnerability], db: AsyncSession) -> tuple[list[dict], dict[str, str]]:
    all_cves = []
    seen_cve_ids = set()
    keyword_to_cve: dict[str, str] = {}
    for v in vulns:
        keyword = v.crypto_feature or v.rule_id
        if not keyword:
            continue
        cves = await map_vulnerability_to_cves(keyword)
        for cve in cves:
            cve_id = cve.get("cve_id")
            if cve_id:
                if keyword not in keyword_to_cve:
                    keyword_to_cve[keyword] = cve_id
                if cve_id not in seen_cve_ids:
                    seen_cve_ids.add(cve_id)
                    all_cves.append(cve)
                    existing = await db.get(CVEEntry, cve_id)
                    if not existing:
                        entry = CVEEntry(
                            cve_id=cve_id,
                            summary=cve.get("summary"),
                            cvss_score=cve.get("cvss_score"),
                            published_date=None,
                        )
                        db.add(entry)
    return all_cves, keyword_to_cve
