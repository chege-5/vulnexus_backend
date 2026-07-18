from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.config import BASE_DIR


REQUIRED_RULE_FIELDS = {
    "id",
    "title",
    "category",
    "severity",
    "confidence",
    "languages",
    "regex",
    "cwe",
    "owasp",
    "recommendation",
    "references",
    "enabled",
}

VALID_SEVERITIES = {"Info", "Low", "Medium", "High", "Critical"}
VALID_LANGUAGES = {
    "generic", "python", "javascript", "typescript", "java", "kotlin", "php", "ruby", "go", "c", "cpp",
    "yaml", "json", "toml", "ini", "shell", "nginx", "apache", "openssl", "terraform",
}
RUNTIME_ONLY_RULE_IDS = {
    "EXPIRED_CERT_LITERAL", "SELF_SIGNED_CERT_LITERAL", "MISSING_HSTS_LITERAL", "WEAK_HSTS_LITERAL",
    "MISSING_CSP_LITERAL", "MISSING_HSTS_HEADER_LITERAL", "MISSING_X_FRAME_OPTIONS_LITERAL",
    "MISSING_X_CONTENT_TYPE_LITERAL", "MISSING_REFERRER_POLICY_LITERAL", "MISSING_PERMISSIONS_POLICY_LITERAL",
    "MISSING_COOP_LITERAL", "MISSING_COEP_LITERAL", "MISSING_CORP_LITERAL", "MISSING_CACHE_CONTROL_LITERAL",
}


class RuleValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ScannerRule:
    id: str
    title: str
    category: str
    severity: str
    confidence: float
    cvss_hint: float | None
    languages: tuple[str, ...]
    regex: tuple[str, ...]
    cwe: tuple[str, ...]
    owasp: str
    recommendation: str
    references: tuple[str, ...]
    enabled: bool
    pack: str
    category_key: str
    confidence_label: str = "probable"
    crypto_feature: str | None = None
    numeric_group_below: int | None = None
    config_only: bool = False
    file_config_only: bool = False
    source_configuration_rule: bool = False
    requires_review: bool = False
    priority: int = 0
    dedupe_group: str | None = None
    compiled_regex: tuple[re.Pattern[str], ...] = field(default_factory=tuple, compare=False)


@dataclass(frozen=True)
class RulePack:
    version: str
    path: Path
    rules: tuple[ScannerRule, ...]


def default_rule_paths() -> list[Path]:
    builtin_pack = BASE_DIR / "app" / "scanner_rules" / "scanner_rules.yml"
    paths = [builtin_pack] if builtin_pack.exists() else []
    custom_dir = BASE_DIR / "scanner_rules"
    if custom_dir.exists():
        paths.extend(sorted(custom_dir.glob("*.yml")))
        paths.extend(sorted(custom_dir.glob("*.yaml")))
    return paths


@lru_cache(maxsize=1)
def load_scanner_rules() -> tuple[ScannerRule, ...]:
    rules: list[ScannerRule] = []
    seen_ids: set[str] = set()
    for path in default_rule_paths():
        if not path.exists():
            continue
        pack = load_master_rule_pack(path) if path.name == "scanner_rules.yml" else load_rule_pack(path)
        for rule in pack.rules:
            if rule.id in seen_ids:
                raise RuleValidationError(f"Duplicate scanner rule id {rule.id!r} in {path}")
            seen_ids.add(rule.id)
            if rule.enabled and rule.id not in RUNTIME_ONLY_RULE_IDS:
                rules.append(rule)
    return tuple(rules)


def load_rule_pack(path: str | Path) -> RulePack:
    rule_path = Path(path)
    try:
        data = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleValidationError(f"Malformed YAML in {rule_path}: {exc}") from exc
    except OSError as exc:
        raise RuleValidationError(f"Unable to read rule pack {rule_path}: {exc}") from exc

    if not isinstance(data, dict):
        raise RuleValidationError(f"Rule pack {rule_path} must be a mapping")
    version = data.get("version")
    categories = data.get("categories")
    if not isinstance(version, str) or not version:
        raise RuleValidationError(f"Rule pack {rule_path} is missing a string version")
    if not isinstance(categories, dict) or not categories:
        raise RuleValidationError(f"Rule pack {rule_path} must define categories")

    rules: list[ScannerRule] = []
    for category_key, category_rules in categories.items():
        if not isinstance(category_rules, list):
            raise RuleValidationError(f"Category {category_key!r} in {rule_path} must be a list")
        for index, raw_rule in enumerate(category_rules):
            rules.append(_validate_rule(raw_rule, category_key=str(category_key), index=index, path=rule_path))
    return RulePack(version=version, path=rule_path, rules=tuple(rules))


def load_master_rule_pack(path: str | Path) -> RulePack:
    """Load the authoritative manifest and each referenced pack exactly once."""
    manifest_path = Path(path)
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RuleValidationError(f"Unable to load rule manifest {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("version"), str):
        raise RuleValidationError(f"Rule manifest {manifest_path} must define a version")
    packs = manifest.get("packs")
    if not isinstance(packs, list) or not packs:
        raise RuleValidationError(f"Rule manifest {manifest_path} must define non-empty packs")

    rules: list[ScannerRule] = []
    for entry in packs:
        if not isinstance(entry, dict):
            raise RuleValidationError(f"Rule manifest {manifest_path} contains an invalid pack entry")
        pack_id = _required_str(entry, "id", str(manifest_path))
        relative_path = _required_str(entry, "path", str(manifest_path))
        priority = entry.get("priority", 0)
        if not isinstance(priority, int):
            raise RuleValidationError(f"Rule manifest {manifest_path} priority for {pack_id!r} must be an integer")
        source = manifest_path.parent / relative_path
        loaded = load_rule_pack(source)
        rules.extend(
            ScannerRule(
                **{**rule.__dict__, "pack": pack_id, "priority": priority + rule.priority}
            )
            for rule in loaded.rules
        )
    return RulePack(version=manifest["version"], path=manifest_path, rules=tuple(rules))


def _validate_rule(raw_rule: Any, *, category_key: str, index: int, path: Path) -> ScannerRule:
    location = f"{path}:{category_key}[{index}]"
    if not isinstance(raw_rule, dict):
        raise RuleValidationError(f"{location} must be a mapping")
    missing = REQUIRED_RULE_FIELDS - set(raw_rule)
    if missing:
        raise RuleValidationError(f"{location} is missing required fields: {', '.join(sorted(missing))}")

    rule_id = _required_str(raw_rule, "id", location)
    title = _required_str(raw_rule, "title", location)
    category = _required_str(raw_rule, "category", location)
    severity = _required_str(raw_rule, "severity", location)
    if severity not in VALID_SEVERITIES:
        raise RuleValidationError(f"{location} has invalid severity {severity!r}")

    confidence = _required_float(raw_rule, "confidence", location)
    if not 0 <= confidence <= 1:
        raise RuleValidationError(f"{location} confidence must be between 0 and 1")
    cvss_value = raw_rule.get("cvss_hint", raw_rule.get("cvss"))
    if cvss_value is None:
        raise RuleValidationError(f"{location} must define cvss_hint (or legacy cvss)")
    cvss_hint = _required_float({"cvss_hint": cvss_value}, "cvss_hint", location)
    if not 0 <= cvss_hint <= 10:
        raise RuleValidationError(f"{location} cvss_hint must be between 0 and 10")

    regexes = _string_tuple(raw_rule["regex"], "regex", location)
    compiled: list[re.Pattern[str]] = []
    for pattern in regexes:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error as exc:
            raise RuleValidationError(f"{location} has invalid regex {pattern!r}: {exc}") from exc

    languages = _string_tuple(raw_rule["languages"], "languages", location)
    invalid_languages = set(languages) - VALID_LANGUAGES
    if invalid_languages:
        raise RuleValidationError(f"{location} has invalid languages: {', '.join(sorted(invalid_languages))}")
    if not isinstance(raw_rule["enabled"], bool):
        raise RuleValidationError(f"{location} field 'enabled' must be a boolean")

    return ScannerRule(
        id=rule_id,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        cvss_hint=cvss_hint,
        languages=languages,
        regex=regexes,
        cwe=_string_tuple(raw_rule["cwe"], "cwe", location),
        owasp=_required_str(raw_rule, "owasp", location),
        recommendation=_required_str(raw_rule, "recommendation", location),
        references=_string_tuple(raw_rule["references"], "references", location),
        enabled=raw_rule["enabled"],
        pack=path.name,
        category_key=category_key,
        confidence_label=str(raw_rule.get("confidence_label") or "probable"),
        crypto_feature=raw_rule.get("crypto_feature"),
        numeric_group_below=_optional_int(raw_rule.get("numeric_group_below"), location, "numeric_group_below"),
        config_only=bool(raw_rule.get("config_only", False)),
        file_config_only=bool(raw_rule.get("file_config_only", raw_rule.get("config_only", False))),
        source_configuration_rule=bool(raw_rule.get("source_configuration_rule", False)),
        requires_review=bool(raw_rule.get("requires_review", False)),
        priority=_optional_int(raw_rule.get("priority", 0), location, "priority") or 0,
        dedupe_group=_optional_str(raw_rule.get("dedupe_group"), location, "dedupe_group"),
        compiled_regex=tuple(compiled),
    )


def _required_str(raw_rule: dict, key: str, location: str) -> str:
    value = raw_rule.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuleValidationError(f"{location} field {key!r} must be a non-empty string")
    return value


def _required_float(raw_rule: dict, key: str, location: str) -> float:
    value = raw_rule.get(key)
    if not isinstance(value, (int, float)):
        raise RuleValidationError(f"{location} field {key!r} must be numeric")
    return float(value)


def _optional_int(value: Any, location: str, key: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int):
        raise RuleValidationError(f"{location} field {key!r} must be an integer")
    return value


def _optional_str(value: Any, location: str, key: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise RuleValidationError(f"{location} field {key!r} must be a non-empty string")
    return value


def _string_tuple(value: Any, key: str, location: str) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        return tuple(value)
    raise RuleValidationError(f"{location} field {key!r} must be a string or non-empty string list")
