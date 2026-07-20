"""SAST facade for the syntax-aware semantic analysis engine.

No finding is made by a regular expression.  Detection comes from parsed
Python ASTs or token streams; this module maps semantic hits to the versioned
YAML rule catalogue and produces safely redacted evidence.
"""
from __future__ import annotations

import math
from pathlib import Path

from app.models.pydantic_models import CryptoFeatures, RuleVulnerability
from app.services.rule_loader import ScannerRule, load_scanner_rules
from app.services.semantic_engine import SemanticMatch, analyze
from app.utils.logger import get_logger
from app.utils.redaction import redact_text

logger = get_logger(__name__)

EXCLUDED_PATH_PARTS = {"node_modules", "vendor", "dist", "build", ".git", "__pycache__"}
EXCLUDED_SUFFIXES = (".lock", ".min.js", ".map")
MAX_FINDINGS_PER_FILE = 25
MAX_MATCHES_PER_RULE_PER_FILE = 25


def scan_file_content(content: str, file_path: str) -> tuple[list[RuleVulnerability], CryptoFeatures]:
    features = CryptoFeatures()
    if _is_excluded_path(file_path):
        return [], features

    rule_index = {rule.id: rule for rule in load_scanner_rules()}
    matches = [
        item for item in analyze(content, file_path)
        if item.rule_id in rule_index
        and not (rule_index[item.rule_id].category == "Weak hashing" and "checksum" in item.matched_text.lower())
    ]
    per_rule: dict[str, int] = {}
    accepted: list[SemanticMatch] = []
    suppressed: dict[str, int] = {}
    for item in matches:
        count = per_rule.get(item.rule_id, 0)
        if count >= MAX_MATCHES_PER_RULE_PER_FILE:
            suppressed[item.rule_id] = suppressed.get(item.rule_id, 0) + 1
            continue
        per_rule[item.rule_id] = count + 1
        accepted.append(item)

    accepted.sort(key=lambda item: (-_severity_rank(rule_index[item.rule_id].severity), item.line_number, item.column_number, item.rule_id))
    omitted = max(0, len(accepted) - MAX_FINDINGS_PER_FILE)
    findings = [
        _make_vulnerability(item, rule_index[item.rule_id], content, file_path, occurrence, omitted + suppressed.get(item.rule_id, 0))
        for occurrence, item in enumerate(accepted[:MAX_FINDINGS_PER_FILE], 1)
    ]
    for finding in findings:
        _update_features(features, finding)
    return findings, features


def scan_files(file_paths: list[str]) -> tuple[list[RuleVulnerability], list[CryptoFeatures]]:
    all_findings: list[RuleVulnerability] = []
    all_features: list[CryptoFeatures] = []
    for path in file_paths:
        try:
            findings, features = scan_file_content(Path(path).read_text(errors="ignore"), path)
            all_findings.extend(findings)
            all_features.append(features)
        except OSError as exc:
            logger.warning("Unable to scan file %s: %s", path, exc)
    return all_findings, all_features


def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    frequencies = [0] * 256
    for value in data:
        frequencies[value] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in frequencies if count)


def _make_vulnerability(match: SemanticMatch, rule: ScannerRule, content: str, file_path: str, occurrence: int, suppressed_count: int) -> RuleVulnerability:
    lines = content.splitlines()
    preview = lines[match.line_number - 1] if 0 < match.line_number <= len(lines) else match.matched_text
    confidence = min(0.99, max(0.05, rule.confidence + match.confidence_delta))
    confidence_label = "confirmed" if match.analyzer in {"python-ast", "token-literal", "configuration-token"} else "probable"
    severity = rule.severity
    if rule.category == "Weak hashing" and "checksum" in preview.lower():
        confidence, confidence_label, severity = 0.45, "informational", "Low"
    evidence = {
        "rule_id": rule.id,
        "source_rule_id": rule.id,
        "rule_name": rule.title,
        "category": rule.category,
        "analysis_engine": match.analyzer,
        "detection_method": "syntax-aware semantic analysis",
        "line_number": match.line_number,
        "column_number": match.column_number,
        "line_preview": redact_text(preview.strip())[:240],
        "context_preview": redact_text(_context(lines, match.line_number))[:800],
        "matched_text": redact_text(match.matched_text)[:240],
        "occurrence": occurrence,
        "occurrence_count": 1,
        "suppressed_count": suppressed_count,
        "rule_pack": rule.pack,
        "cvss_hint": rule.cvss_hint,
        "requires_review": rule.requires_review,
    }
    return RuleVulnerability(
        rule_id=rule.id,
        title=rule.title,
        category=rule.category,
        description=f"{rule.title}. {rule.recommendation}",
        severity=severity,
        file_path=file_path,
        line_number=match.line_number,
        column_number=match.column_number,
        crypto_feature=rule.crypto_feature,
        confidence=confidence,
        confidence_label=confidence_label,
        default_severity=rule.severity,
        cvss_hint=rule.cvss_hint,
        requires_review=rule.requires_review,
        evidence=evidence,
        explanation=f"{rule.title}. {rule.recommendation}",
        remediation=rule.recommendation,
        recommendation=rule.recommendation,
        cwe_ids=list(rule.cwe),
        owasp_category=rule.owasp,
        references=[rule.owasp, *rule.cwe, *rule.references],
    )


def _context(lines: list[str], line: int, radius: int = 2) -> str:
    return "\n".join(lines[max(0, line - radius - 1):min(len(lines), line + radius)])


def _update_features(features: CryptoFeatures, finding: RuleVulnerability) -> None:
    rule_id = finding.rule_id
    if "MD5" in rule_id:
        features.uses_md5 = finding.confidence >= 0.7
    elif "SHA1" in rule_id or "SHA_1" in rule_id:
        features.uses_sha1 = finding.confidence >= 0.7
    elif any(term in rule_id for term in ("DES", "RC4", "ECB")):
        features.uses_des = "DES" in rule_id
        features.uses_rc2 = "RC4" in rule_id
        features.uses_ecb = "ECB" in rule_id
    elif "RSA" in rule_id and "KEY" in rule_id:
        features.rsa_key_small = "SMALL" in rule_id
    elif finding.category == "Hardcoded keys":
        features.hardcoded_key = True
    elif finding.category == "Insecure randomness":
        features.insecure_random = True


def _is_excluded_path(file_path: str) -> bool:
    normalized = file_path.replace("\\", "/").lower()
    path = Path(normalized)
    return normalized.endswith(EXCLUDED_SUFFIXES) or any(part in EXCLUDED_PATH_PARTS for part in path.parts)


def _severity_rank(value: str) -> int:
    return {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}.get(value, 0)
