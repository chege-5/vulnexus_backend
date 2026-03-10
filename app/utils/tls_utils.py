import ssl
import socket
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class TLSInfo:
    tls_version: str = "unknown"
    cipher_suite: str = "unknown"
    cipher_bits: int = 0
    cert_subject: dict = field(default_factory=dict)
    cert_issuer: dict = field(default_factory=dict)
    cert_not_before: Optional[datetime] = None
    cert_not_after: Optional[datetime] = None
    cert_valid_days: int = 0
    cert_sig_algorithm: str = "unknown"
    self_signed: bool = False
    forward_secrecy: bool = False
    cert_expired: bool = False


def get_tls_info(hostname: str, port: int = 443, timeout: float = 10.0) -> TLSInfo:
    # CERT_NONE is intentional: the scanner must connect to hosts with
    # invalid/self-signed/expired certs in order to inspect them.
    info = TLSInfo()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                info.tls_version = ssock.version() or "unknown"
                cipher = ssock.cipher()
                if cipher:
                    info.cipher_suite = cipher[0]
                    info.cipher_bits = cipher[2] if len(cipher) > 2 else 0

                cert_bin = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()

                if cert_dict:
                    info.cert_subject = _parse_cert_dn(cert_dict.get("subject", ()))
                    info.cert_issuer = _parse_cert_dn(cert_dict.get("issuer", ()))

                    nb = cert_dict.get("notBefore")
                    na = cert_dict.get("notAfter")
                    if nb:
                        info.cert_not_before = _parse_cert_date(nb)
                    if na:
                        info.cert_not_after = _parse_cert_date(na)
                    if info.cert_not_after:
                        info.cert_valid_days = (info.cert_not_after - datetime.utcnow()).days
                        info.cert_expired = info.cert_valid_days < 0

                    info.self_signed = info.cert_subject == info.cert_issuer

                fs_keywords = ("DHE", "ECDHE")
                info.forward_secrecy = any(k in info.cipher_suite for k in fs_keywords)

                if cert_bin:
                    try:
                        from cryptography import x509
                        cert_obj = x509.load_der_x509_certificate(cert_bin)
                        info.cert_sig_algorithm = cert_obj.signature_algorithm_oid.dotted_string
                    except Exception:
                        pass

    except Exception as e:
        logger.error(f"TLS scan failed for {hostname}:{port}: {e}")

    return info


def _parse_cert_dn(dn_tuple) -> dict:
    result = {}
    for rdn in dn_tuple:
        for attr in rdn:
            result[attr[0]] = attr[1]
    return result


def _parse_cert_date(date_str: str) -> datetime:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return datetime.utcnow()


def check_hsts(hostname: str) -> bool:
    import httpx
    from app.config import settings
    try:
        r = httpx.get(
            f"https://{hostname}",
            timeout=10,
            follow_redirects=True,
            verify=settings.VERIFY_SCAN_TARGETS,
        )
        return "strict-transport-security" in {k.lower() for k in r.headers.keys()}
    except Exception:
        return False
