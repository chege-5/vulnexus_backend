import re
import math
from pathlib import Path
from typing import Optional
from app.models.pydantic_models import CryptoFeatures, RuleVulnerability
from app.utils.logger import get_logger

logger = get_logger(__name__)

WEAK_HASH_PATTERNS = [
    (r'\bMD5\b|\.md5\(|hashlib\.md5|MessageDigest\.getInstance\(\s*"MD5"', "MD5"),
    (r'\bSHA[\-_]?1\b|\.sha1\(|hashlib\.sha1|MessageDigest\.getInstance\(\s*"SHA-1"', "SHA1"),
]

WEAK_CIPHER_PATTERNS = [
    (r'\bDES\b|DESede|DES/|Cipher\.getInstance\(\s*"DES', "DES"),
    (r'\bRC2\b|RC2/|Cipher\.getInstance\(\s*"RC2', "RC2"),
    (r'AES/ECB|AES\.MODE_ECB|"AES/ECB/', "AES-ECB"),
]

SMALL_KEY_PATTERNS = [
    (r'RSA.*?(?:keysize|key_size|bits)\s*[=:]\s*(\d+)', "RSA"),
    (r'AES.*?(?:keysize|key_size|bits|length)\s*[=:]\s*(\d+)', "AES"),
    (r'generate_private_key.*?key_size\s*=\s*(\d+)', "RSA"),
]

HARDCODED_KEY_PATTERNS = [
    r'(?:secret|api|private|encryption|aes|des|key|password|token)[\s_]*[=:]\s*["\'][A-Za-z0-9+/=]{16,}["\']',
    r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
    r'(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}',
]

INSECURE_RANDOM_PATTERNS = [
    r'\brandom\.random\b|\brandom\.randint\b|\bMath\.random\b|\bjava\.util\.Random\b',
    r'\brand\(\)|\bsrand\(',
]


def scan_file_content(content: str, file_path: str) -> tuple[list[RuleVulnerability], CryptoFeatures]:
    vulns: list[RuleVulnerability] = []
    features = CryptoFeatures()

    lines = content.split("\n")

    for pattern, name in WEAK_HASH_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                vuln = RuleVulnerability(
                    rule_id=f"WEAK_HASH_{name}",
                    description=f"Weak hash algorithm {name} detected",
                    severity="Medium",
                    file_path=file_path,
                    line_number=i,
                    crypto_feature=name,
                )
                vulns.append(vuln)
                if name == "MD5":
                    features.uses_md5 = True
                elif name == "SHA1":
                    features.uses_sha1 = True
                break

    for pattern, name in WEAK_CIPHER_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                vuln = RuleVulnerability(
                    rule_id=f"WEAK_CIPHER_{name}",
                    description=f"Weak cipher {name} detected",
                    severity="High",
                    file_path=file_path,
                    line_number=i,
                    crypto_feature=name,
                )
                vulns.append(vuln)
                if name == "DES":
                    features.uses_des = True
                elif name == "RC2":
                    features.uses_rc2 = True
                elif name == "AES-ECB":
                    features.uses_ecb = True
                break

    for pattern, key_type in SMALL_KEY_PATTERNS:
        for i, line in enumerate(lines, 1):
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                try:
                    size = int(m.group(1))
                except (IndexError, ValueError):
                    continue
                features.key_size = size
                if key_type == "RSA" and size < 2048:
                    features.rsa_key_small = True
                    vulns.append(RuleVulnerability(
                        rule_id="SMALL_RSA_KEY",
                        description=f"RSA key size {size} bits is below 2048",
                        severity="High",
                        file_path=file_path,
                        line_number=i,
                        crypto_feature=f"RSA-{size}",
                    ))
                elif key_type == "AES" and size < 128:
                    features.aes_key_small = True
                    vulns.append(RuleVulnerability(
                        rule_id="SMALL_AES_KEY",
                        description=f"AES key size {size} bits is below 128",
                        severity="High",
                        file_path=file_path,
                        line_number=i,
                        crypto_feature=f"AES-{size}",
                    ))
                break

    for pattern in HARDCODED_KEY_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                features.hardcoded_key = True
                vulns.append(RuleVulnerability(
                    rule_id="HARDCODED_KEY",
                    description="Hardcoded cryptographic key or secret detected",
                    severity="Critical",
                    file_path=file_path,
                    line_number=i,
                ))
                break
        if features.hardcoded_key:
            break

    for pattern in INSECURE_RANDOM_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                features.insecure_random = True
                vulns.append(RuleVulnerability(
                    rule_id="INSECURE_RANDOM",
                    description="Insecure random number generator used in cryptographic context",
                    severity="Medium",
                    file_path=file_path,
                    line_number=i,
                ))
                break
        if features.insecure_random:
            break

    return vulns, features


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
            logger.error(f"Error scanning {fp}: {e}")
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
