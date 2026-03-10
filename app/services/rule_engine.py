from app.models.pydantic_models import RuleVulnerability, CryptoFeatures
from app.utils.logger import get_logger

logger = get_logger(__name__)

RULES = [
    {"condition": lambda f: f.rsa_key_small, "rule_id": "RSA_SMALL", "desc": "RSA key size below 2048 bits", "severity": "High", "score": 30},
    {"condition": lambda f: f.aes_key_small, "rule_id": "AES_SMALL", "desc": "AES key size below 128 bits", "severity": "High", "score": 30},
    {"condition": lambda f: f.uses_md5, "rule_id": "USES_MD5", "desc": "MD5 hash algorithm usage detected", "severity": "Medium", "score": 20},
    {"condition": lambda f: f.uses_sha1, "rule_id": "USES_SHA1", "desc": "SHA-1 hash algorithm usage detected", "severity": "Medium", "score": 20},
    {"condition": lambda f: f.uses_des, "rule_id": "USES_DES", "desc": "DES cipher usage detected", "severity": "High", "score": 30},
    {"condition": lambda f: f.uses_rc2, "rule_id": "USES_RC2", "desc": "RC2 cipher usage detected", "severity": "High", "score": 25},
    {"condition": lambda f: f.uses_ecb, "rule_id": "USES_ECB", "desc": "ECB cipher mode usage detected", "severity": "High", "score": 25},
    {"condition": lambda f: f.hardcoded_key, "rule_id": "HARDCODED_KEY", "desc": "Hardcoded cryptographic key detected", "severity": "Critical", "score": 40},
    {"condition": lambda f: f.insecure_random, "rule_id": "INSECURE_RANDOM", "desc": "Insecure random number generator", "severity": "Medium", "score": 15},
    {"condition": lambda f: f.self_signed is True, "rule_id": "SELF_SIGNED", "desc": "Self-signed certificate detected", "severity": "High", "score": 25},
    {"condition": lambda f: f.has_hsts is False and f.has_hsts is not None, "rule_id": "NO_HSTS", "desc": "HSTS header missing", "severity": "Low", "score": 10},
    {"condition": lambda f: f.forward_secrecy is False and f.forward_secrecy is not None, "rule_id": "NO_PFS", "desc": "No forward secrecy", "severity": "Medium", "score": 15},
    {"condition": lambda f: f.tls_version in ("TLSv1", "TLSv1.0", "TLSv1.1"), "rule_id": "WEAK_TLS", "desc": "Weak TLS version", "severity": "High", "score": 30},
]


def evaluate_rules(features_list: list[CryptoFeatures]) -> tuple[list[RuleVulnerability], float]:
    vulns = []
    total_score = 0.0
    seen_rules = set()

    for features in features_list:
        for rule in RULES:
            try:
                if rule["condition"](features) and rule["rule_id"] not in seen_rules:
                    seen_rules.add(rule["rule_id"])
                    vulns.append(RuleVulnerability(
                        rule_id=rule["rule_id"],
                        description=rule["desc"],
                        severity=rule["severity"],
                    ))
                    total_score += rule["score"]
            except Exception:
                continue

    rule_score = min(total_score, 100.0)
    return vulns, rule_score


def compute_rule_score(features: CryptoFeatures) -> float:
    score = 0.0
    for rule in RULES:
        try:
            if rule["condition"](features):
                score += rule["score"]
        except Exception:
            continue
    return min(score, 100.0)
