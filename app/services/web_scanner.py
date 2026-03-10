import asyncio
import httpx
from urllib.parse import urlparse
from app.models.pydantic_models import CryptoFeatures, RuleVulnerability
from app.utils.tls_utils import get_tls_info, check_hsts, TLSInfo
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

TLS_VERSION_MAP = {
    "TLSv1": 1.0,
    "TLSv1.0": 1.0,
    "TLSv1.1": 1.1,
    "TLSv1.2": 1.2,
    "TLSv1.3": 1.3,
}


async def scan_url(target_url: str) -> tuple[list[RuleVulnerability], CryptoFeatures]:
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or 443

    if not hostname:
        raise ValueError("Invalid URL: no hostname")

    tls_info = await asyncio.to_thread(get_tls_info, hostname, port)
    has_hsts = await asyncio.to_thread(check_hsts, hostname)

    features = _extract_features(tls_info, has_hsts)
    vulns = _analyze_tls(tls_info, has_hsts, target_url)

    ssl_labs_vulns = await _call_ssl_labs(hostname)
    vulns.extend(ssl_labs_vulns)

    header_vulns = await _check_security_headers(target_url)
    vulns.extend(header_vulns)

    return vulns, features


def _extract_features(tls_info: TLSInfo, has_hsts: bool) -> CryptoFeatures:
    tls_ver = tls_info.tls_version
    return CryptoFeatures(
        tls_version=tls_ver,
        cert_valid_days=tls_info.cert_valid_days,
        forward_secrecy=tls_info.forward_secrecy,
        has_hsts=has_hsts,
        self_signed=tls_info.self_signed,
        cipher_mode=tls_info.cipher_suite,
        key_size=tls_info.cipher_bits,
    )


def _analyze_tls(tls_info: TLSInfo, has_hsts: bool, url: str) -> list[RuleVulnerability]:
    vulns = []
    ver_num = TLS_VERSION_MAP.get(tls_info.tls_version, 0)

    if 0 < ver_num < 1.2:
        vulns.append(RuleVulnerability(
            rule_id="WEAK_TLS_VERSION",
            description=f"Weak TLS version {tls_info.tls_version} detected on {url}",
            severity="High",
            crypto_feature=tls_info.tls_version,
        ))

    if tls_info.self_signed:
        vulns.append(RuleVulnerability(
            rule_id="SELF_SIGNED_CERT",
            description=f"Self-signed certificate detected on {url}",
            severity="High",
            crypto_feature="self-signed",
        ))

    if tls_info.cert_expired:
        vulns.append(RuleVulnerability(
            rule_id="EXPIRED_CERT",
            description=f"Expired certificate on {url}",
            severity="Critical",
            crypto_feature="expired-cert",
        ))

    if not tls_info.forward_secrecy:
        vulns.append(RuleVulnerability(
            rule_id="NO_FORWARD_SECRECY",
            description=f"No forward secrecy on {url}",
            severity="Medium",
            crypto_feature="no-pfs",
        ))

    if not has_hsts:
        vulns.append(RuleVulnerability(
            rule_id="NO_HSTS",
            description=f"HSTS header missing on {url}",
            severity="Low",
            crypto_feature="no-hsts",
        ))

    weak_ciphers = ("RC4", "DES", "3DES", "NULL", "EXPORT", "anon")
    if any(w in tls_info.cipher_suite.upper() for w in weak_ciphers):
        vulns.append(RuleVulnerability(
            rule_id="WEAK_CIPHER_SUITE",
            description=f"Weak cipher suite {tls_info.cipher_suite} on {url}",
            severity="High",
            crypto_feature=tls_info.cipher_suite,
        ))

    return vulns


async def _call_ssl_labs(hostname: str) -> list[RuleVulnerability]:
    vulns = []
    try:
        url = f"{settings.SSL_LABS_API_URL}/analyze"
        params = {"host": hostname, "fromCache": "on", "all": "done"}
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(url, params=params)
            if r.status_code == 200:
                data = r.json()
                endpoints = data.get("endpoints", [])
                for ep in endpoints:
                    grade = ep.get("grade", "")
                    if grade and grade not in ("A+", "A", "A-"):
                        vulns.append(RuleVulnerability(
                            rule_id="SSL_LABS_GRADE",
                            description=f"SSL Labs grade {grade} for {hostname}",
                            severity="Medium" if grade.startswith("B") else "High",
                            crypto_feature=f"ssl-grade-{grade}",
                        ))
    except Exception as e:
        logger.warning(f"SSL Labs API call failed: {e}")
    return vulns


async def _check_security_headers(url: str) -> list[RuleVulnerability]:
    vulns = []
    try:
        async with httpx.AsyncClient(
            timeout=10,
            follow_redirects=True,
            verify=settings.VERIFY_SCAN_TARGETS,
        ) as client:
            r = await client.get(url)
            headers_lower = {k.lower(): v for k, v in r.headers.items()}

            checks = [
                ("x-content-type-options", "MISSING_X_CONTENT_TYPE", "X-Content-Type-Options header missing"),
                ("x-frame-options", "MISSING_X_FRAME_OPTIONS", "X-Frame-Options header missing"),
                ("content-security-policy", "MISSING_CSP", "Content-Security-Policy header missing"),
            ]
            for header, rule_id, desc in checks:
                if header not in headers_lower:
                    vulns.append(RuleVulnerability(
                        rule_id=rule_id,
                        description=desc,
                        severity="Low",
                    ))
    except Exception as e:
        logger.warning(f"Security headers check failed: {e}")
    return vulns
