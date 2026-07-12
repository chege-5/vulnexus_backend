from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path

from app.config import settings
from app.models.pydantic_models import CryptoFeatures, RuleVulnerability
from app.services.rule_loader import ScannerRule, load_scanner_rules
from app.utils.logger import get_logger
from app.utils.redaction import redact_text

logger = get_logger(__name__)

SECURITY_CONTEXT_TERMS = (
    "password", "passwd", "secret", "token", "sign", "signature", "auth", "credential",
    "session", "jwt", "hmac", "certificate", "encrypt", "decrypt", "key", "salt", "iv",
    "csrf", "reset", "otp", "bearer", "oauth",
)
NON_SECURITY_CONTEXT_TERMS = ("checksum", "etag", "cache", "dedupe", "fingerprint", "nonsecurity", "non-security")
CONFIG_SUFFIXES = (".env", ".yml", ".yaml", ".json", ".toml", ".tf", ".ini", ".conf")
EXCLUDED_PATH_PARTS = {"node_modules", "vendor", "dist", "build", ".git", "__pycache__"}
EXCLUDED_SUFFIXES = (".lock", ".min.js", ".map")
MAX_MATCHES_PER_RULE_PER_FILE = 25
MAX_FINDINGS_PER_FILE = 100


LEGACY_RULE_IDS = {
    "WEAK_HASH_MD5_PY_HASHLIB": "WEAK_HASH_MD5",
    "WEAK_HASH_CRYPTOJS_MD5": "WEAK_HASH_MD5",
    "WEAK_HASH_JAVA_MD5": "WEAK_HASH_MD5",
    "WEAK_HASH_NODE_MD5": "WEAK_HASH_MD5",
    "WEAK_HASH_SHA1_PY_HASHLIB": "WEAK_HASH_SHA1",
    "WEAK_HASH_CRYPTOJS_SHA1": "WEAK_HASH_SHA1",
    "WEAK_HASH_JAVA_SHA1": "WEAK_HASH_SHA1",
    "WEAK_HASH_NODE_SHA1": "WEAK_HASH_SHA1",
    "HARDCODED_AWS_ACCESS_KEY": "HARDCODED_KEY",
    "HARDCODED_AWS_SECRET_KEY": "HARDCODED_KEY",
    "HARDCODED_AZURE_CLIENT_SECRET": "HARDCODED_KEY",
    "HARDCODED_AZURE_TENANT_SECRET": "HARDCODED_KEY",
    "HARDCODED_GCP_PRIVATE_KEY": "HARDCODED_KEY",
    "HARDCODED_GCP_PRIVATE_KEY_ID": "HARDCODED_KEY",
    "HARDCODED_JWT_SECRET": "HARDCODED_KEY",
    "HARDCODED_OAUTH_SECRET": "HARDCODED_KEY",
    "HARDCODED_BEARER_TOKEN": "HARDCODED_KEY",
    "HARDCODED_API_KEY": "HARDCODED_KEY",
    "HARDCODED_SSH_PRIVATE_KEY": "HARDCODED_KEY",
    "HARDCODED_RSA_PRIVATE_KEY": "HARDCODED_KEY",
    "HARDCODED_EC_PRIVATE_KEY": "HARDCODED_KEY",
    "HARDCODED_DATABASE_URL": "HARDCODED_KEY",
    "HARDCODED_MONGO_URI": "HARDCODED_KEY",
    "HARDCODED_POSTGRES_URI": "HARDCODED_KEY",
    "HARDCODED_MYSQL_URI": "HARDCODED_KEY",
    "HARDCODED_REDIS_PASSWORD": "HARDCODED_KEY",
    "INSECURE_RANDOM_PY_RANDOM": "INSECURE_RANDOM",
    "INSECURE_RANDOM_PY_RANDINT": "INSECURE_RANDOM",
    "INSECURE_RANDOM_PY_CHOICE": "INSECURE_RANDOM",
    "INSECURE_RANDOM_JS_MATH_RANDOM": "INSECURE_RANDOM",
    "INSECURE_RANDOM_JAVA_UTIL_RANDOM": "INSECURE_RANDOM",
    "INSECURE_RANDOM_JAVA_NEW_RANDOM": "INSECURE_RANDOM",
    "INSECURE_RANDOM_PHP_RAND": "INSECURE_RANDOM",
    "INSECURE_RANDOM_PHP_MT_RAND": "INSECURE_RANDOM",
    "INSECURE_RANDOM_PHP_SRAND": "INSECURE_RANDOM",
    "INSECURE_RANDOM_GO_MATH_RAND": "INSECURE_RANDOM",
    "INSECURE_RANDOM_WEAK_UUID_TOKEN": "INSECURE_RANDOM",
    "INSECURE_RANDOM_TIMESTAMP_TOKEN": "INSECURE_RANDOM",
    "WEAK_PBKDF2_ITERATIONS": "WEAK_KDF",
    "WEAK_BCRYPT_ROUNDS": "WEAK_KDF",
}


@dataclass(frozen=True)
class RuleMatch:
    rule: ScannerRule
    line_number: int
    column_number: int
    match_text: str
    pattern: str
    start: int
    end: int
    occurrence: int
    suppressed_count: int = 0


def scan_file_content(content: str, file_path: str) -> tuple[list[RuleVulnerability], CryptoFeatures]:
    features = CryptoFeatures()
    if _is_excluded_path(file_path):
        return [], features

    lines = content.split("\n")
    matches = _find_matches(lines, file_path)
    vulns: list[RuleVulnerability] = []
    suppressed_by_file = max(0, len(matches) - MAX_FINDINGS_PER_FILE)

    for occurrence, match in enumerate(matches[:MAX_FINDINGS_PER_FILE], 1):
        vuln = _make_vulnerability(match, lines, file_path, occurrence, suppressed_by_file + match.suppressed_count)
        vulns.append(vuln)
        _update_features(features, match.rule, match.match_text)

    return vulns, [features][0]


def scan_files(file_paths: list[str]) -> tuple[list[RuleVulnerability], list[CryptoFeatures]]:
    all_vulns = []
    all_features = []
    for fp in file_paths:
        try:
            content = Path(fp).read_text(errors="ignore")
            vulns, features = scan_file_content(content, fp)
            all_vulns.extend(vulns)
            all_features.append(features)
        except Exception as e:
            logger.error("Error scanning %s: %s", fp, e)
    return all_vulns, all_features


def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _find_matches(lines: list[str], file_path: str) -> list[RuleMatch]:
    lower_path = file_path.lower()
    all_matches: list[RuleMatch] = []
    seen: set[tuple[str, str, int, str]] = set()
    occupied_spans: dict[int, list[tuple[int, int]]] = {}
    per_rule_counts: dict[str, int] = {}
    per_rule_suppressed: dict[str, int] = {}

    for rule in load_scanner_rules():
        if rule.config_only and not _looks_like_config(lower_path):
            continue
        for line_number, line in enumerate(lines, 1):
            for pattern, compiled in zip(rule.regex, rule.compiled_regex):
                for match in compiled.finditer(line):
                    if not _match_allowed(rule, match, lines, line_number, lower_path):
                        continue
                    start, end = match.span()
                    if _overlaps_existing(occupied_spans.get(line_number, []), start, end):
                        continue
                    normalized = redact_text(match.group(0)).strip().lower()
                    legacy_id = _legacy_rule_id(rule.id)
                    dedupe_key = (legacy_id, lower_path, line_number, normalized)
                    if dedupe_key in seen:
                        continue
                    if per_rule_counts.get(rule.id, 0) >= MAX_MATCHES_PER_RULE_PER_FILE:
                        per_rule_suppressed[rule.id] = per_rule_suppressed.get(rule.id, 0) + 1
                        continue
                    seen.add(dedupe_key)
                    occupied_spans.setdefault(line_number, []).append((start, end))
                    per_rule_counts[rule.id] = per_rule_counts.get(rule.id, 0) + 1
                    all_matches.append(RuleMatch(
                        rule=rule,
                        line_number=line_number,
                        column_number=start + 1,
                        match_text=match.group(0),
                        pattern=pattern,
                        start=start,
                        end=end,
                        occurrence=len(all_matches) + 1,
                    ))
    with_suppression = [
        RuleMatch(
            rule=item.rule,
            line_number=item.line_number,
            column_number=item.column_number,
            match_text=item.match_text,
            pattern=item.pattern,
            start=item.start,
            end=item.end,
            occurrence=item.occurrence,
            suppressed_count=per_rule_suppressed.get(item.rule.id, 0),
        )
        for item in all_matches
    ]
    return sorted(with_suppression, key=lambda item: (item.line_number, item.column_number, item.rule.id))


def _match_allowed(rule: ScannerRule, match: re.Match[str], lines: list[str], line_number: int, lower_path: str) -> bool:
    context = _line_context(lines, line_number)
    if rule.id == "WEAK_HASH_CRC32_SECURITY" and not _has_security_context(context):
        return False
    if rule.id == "CBC_WITHOUT_AUTH" and _has_authentication_context(_line_context(lines, line_number, radius=4)):
        return False
    if rule.numeric_group_below is not None and not _captured_number_below(match, rule.numeric_group_below):
        return False
    return True


def _make_vulnerability(
    match: RuleMatch,
    lines: list[str],
    file_path: str,
    occurrence: int,
    suppressed_by_file: int,
) -> RuleVulnerability:
    rule = match.rule
    context = _line_context(lines, match.line_number)
    confidence, label, severity = _adjust_context(rule, context, file_path.lower())
    evidence = _source_evidence(lines, match, extra={
        "rule_id": _legacy_rule_id(rule.id),
        "source_rule_id": rule.id,
        "rule_name": rule.title,
        "category": rule.category,
        "matched_pattern": rule.id,
        "regex": rule.regex[0],
        "matched_text": redact_text(match.match_text),
        "column_number": match.column_number,
        "occurrence": occurrence,
        "occurrence_count": 1,
        "suppressed_count": suppressed_by_file,
        "rule_pack": rule.pack,
        "cvss": rule.cvss,
    })
    return RuleVulnerability(
        rule_id=_legacy_rule_id(rule.id),
        title=rule.title,
        category=rule.category,
        description=_explanation(rule),
        severity=severity,
        file_path=file_path,
        line_number=match.line_number,
        column_number=match.column_number,
        crypto_feature=rule.crypto_feature,
        confidence=confidence,
        confidence_label=label,
        evidence=evidence,
        explanation=_explanation(rule),
        remediation=rule.recommendation,
        recommendation=rule.recommendation,
        cwe_ids=list(rule.cwe),
        owasp_category=rule.owasp,
        references=[rule.owasp, *rule.cwe, *rule.references],
    )


def _adjust_context(rule: ScannerRule, context: str, lower_path: str) -> tuple[float, str, str]:
    if rule.category == "Weak hashing":
        confidence, label = _context_confidence(context)
        severity = "Medium" if confidence >= 0.75 else "Low"
        return max(confidence, rule.confidence if confidence >= 0.75 else 0), label, severity
    if rule.category == "Insecure randomness":
        if _has_security_context(context):
            return rule.confidence, "probable", rule.severity
        return min(rule.confidence, 0.55), "informational", "Low"
    if rule.config_only and _looks_like_config(lower_path):
        return max(rule.confidence, 0.92), "confirmed", "High" if rule.severity == "Low" else rule.severity
    if rule.category == "Hardcoded keys":
        return rule.confidence, "confirmed", rule.severity
    return rule.confidence, rule.confidence_label, rule.severity


def _update_features(features: CryptoFeatures, rule: ScannerRule, match_text: str) -> None:
    legacy_id = _legacy_rule_id(rule.id)
    if legacy_id == "WEAK_HASH_MD5":
        features.uses_md5 = True
    elif legacy_id == "WEAK_HASH_SHA1":
        features.uses_sha1 = True
    elif rule.id == "WEAK_CIPHER_DES":
        features.uses_des = True
    elif rule.id == "WEAK_CIPHER_RC2":
        features.uses_rc2 = True
    elif rule.id == "WEAK_CIPHER_AES-ECB":
        features.uses_ecb = True
    elif legacy_id == "HARDCODED_KEY":
        features.hardcoded_key = True
    elif legacy_id == "INSECURE_RANDOM":
        features.insecure_random = True
    elif rule.id == "SMALL_RSA_KEY":
        features.rsa_key_small = True
        features.key_size = _first_int_from_text(match_text)
    elif rule.id == "SMALL_AES_KEY":
        features.aes_key_small = True
        features.key_size = _first_int_from_text(match_text)


def _line_context(lines: list[str], line_number: int, radius: int = 2) -> str:
    start = max(0, line_number - 1 - radius)
    end = min(len(lines), line_number + radius)
    return "\n".join(lines[start:end])


def _context_confidence(context: str) -> tuple[float, str]:
    lower = context.lower()
    if any(term in lower for term in SECURITY_CONTEXT_TERMS):
        return 0.9, "probable"
    if any(term in lower for term in NON_SECURITY_CONTEXT_TERMS):
        return 0.45, "informational"
    return 0.68, "probable"


def _has_security_context(context: str) -> bool:
    lower = context.lower()
    return any(term in lower for term in SECURITY_CONTEXT_TERMS)


def _has_authentication_context(context: str) -> bool:
    lower = context.lower()
    return any(term in lower for term in ("hmac", "mac", "gcm", "poly1305", "authenticate", "authenticated"))


def _looks_like_config(lower_path: str) -> bool:
    return (
        lower_path.endswith(CONFIG_SUFFIXES)
        or "docker-compose" in lower_path
        or ".github" in lower_path
        or "github\\workflows" in lower_path
        or "github/workflows" in lower_path
    )


def _captured_number_below(match: re.Match[str], threshold: int) -> bool:
    for group in match.groups():
        try:
            return int(group) < threshold
        except (TypeError, ValueError):
            continue
    return False


def _first_int_from_text(value: str) -> int | None:
    found = re.search(r"\d+", value)
    return int(found.group(0)) if found else None


def _source_evidence(lines: list[str], match: RuleMatch, extra: dict | None = None) -> dict:
    line = lines[match.line_number - 1] if 0 < match.line_number <= len(lines) else ""
    evidence = {
        "line_number": match.line_number,
        "column_number": match.column_number,
        "line_preview": redact_text(line.strip())[:240],
        "context_preview": redact_text(_line_context(lines, match.line_number))[:800],
    }
    if extra:
        evidence.update(extra)
    return evidence


def _overlaps_existing(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(start < existing_end and end > existing_start for existing_start, existing_end in spans)


def _is_excluded_path(file_path: str) -> bool:
    lower = file_path.lower()
    path = Path(lower)
    if lower.endswith(EXCLUDED_SUFFIXES):
        return True
    return any(part in EXCLUDED_PATH_PARTS for part in path.parts)


def _legacy_rule_id(rule_id: str) -> str:
    return LEGACY_RULE_IDS.get(rule_id, rule_id)


def _explanation(rule: ScannerRule) -> str:
    return f"{rule.title}. {rule.recommendation}"


def _mask_secret(text: str) -> str:
    return redact_text(text)
