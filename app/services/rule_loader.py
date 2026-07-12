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
    "cvss",
    "languages",
    "regex",
    "cwe",
    "owasp",
    "recommendation",
    "references",
    "enabled",
}

VALID_SEVERITIES = {"Info", "Low", "Medium", "High", "Critical"}


class RuleValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ScannerRule:
    id: str
    title: str
    category: str
    severity: str
    confidence: float
    cvss: float
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
    compiled_regex: tuple[re.Pattern[str], ...] = field(default_factory=tuple, compare=False)


@dataclass(frozen=True)
class RulePack:
    version: str
    path: Path
    rules: tuple[ScannerRule, ...]


def default_rule_paths() -> list[Path]:
    paths = [BASE_DIR / "app" / "scanner_rules" / "crypto_rules.yml"]
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
        pack = load_rule_pack(path)
        for rule in pack.rules:
            if rule.id in seen_ids:
                raise RuleValidationError(f"Duplicate scanner rule id {rule.id!r} in {path}")
            seen_ids.add(rule.id)
            if rule.enabled:
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
    cvss = _required_float(raw_rule, "cvss", location)
    if not 0 <= cvss <= 10:
        raise RuleValidationError(f"{location} cvss must be between 0 and 10")

    regexes = _string_tuple(raw_rule["regex"], "regex", location)
    compiled: list[re.Pattern[str]] = []
    for pattern in regexes:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error as exc:
            raise RuleValidationError(f"{location} has invalid regex {pattern!r}: {exc}") from exc

    return ScannerRule(
        id=rule_id,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        cvss=cvss,
        languages=_string_tuple(raw_rule["languages"], "languages", location),
        regex=regexes,
        cwe=_string_tuple(raw_rule["cwe"], "cwe", location),
        owasp=_required_str(raw_rule, "owasp", location),
        recommendation=_required_str(raw_rule, "recommendation", location),
        references=_string_tuple(raw_rule["references"], "references", location),
        enabled=bool(raw_rule["enabled"]),
        pack=path.name,
        category_key=category_key,
        confidence_label=str(raw_rule.get("confidence_label") or "probable"),
        crypto_feature=raw_rule.get("crypto_feature"),
        numeric_group_below=_optional_int(raw_rule.get("numeric_group_below"), location, "numeric_group_below"),
        config_only=bool(raw_rule.get("config_only", False)),
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


def _string_tuple(value: Any, key: str, location: str) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        return tuple(value)
    raise RuleValidationError(f"{location} field {key!r} must be a string or non-empty string list")
