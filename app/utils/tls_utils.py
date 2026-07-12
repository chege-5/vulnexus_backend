from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, ExtendedKeyUsageOID, NameOID

from app.config import settings
from app.core.http_client import create_sync_client, request_with_retry_sync
from app.utils.logger import get_logger

logger = get_logger(__name__)


TLS_VERSION_ORDER = {"SSLv3": 0.3, "TLSv1": 1.0, "TLSv1.0": 1.0, "TLSv1.1": 1.1, "TLSv1.2": 1.2, "TLSv1.3": 1.3}
TLS_VERSION_MAP = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}
WEAK_CIPHER_TOKENS = ("NULL", "EXPORT", "RC4", "DES", "3DES", "ADH", "AECDH", "ANON", "MD5")
ACCEPTABLE_CIPHER_TOKENS = ("CBC",)
FS_TOKENS = ("ECDHE", "DHE")


@dataclass
class TLSInfo:
    tls_version: str = "unknown"
    cipher_suite: str = "unknown"
    cipher_bits: int = 0
    cert_subject: dict[str, Any] = field(default_factory=dict)
    cert_issuer: dict[str, Any] = field(default_factory=dict)
    cert_not_before: Optional[datetime] = None
    cert_not_after: Optional[datetime] = None
    cert_valid_days: int = 0
    cert_sig_algorithm: str = "unknown"
    self_signed: bool = False
    forward_secrecy: bool = False
    cert_expired: bool = False
    chain_trusted: bool | None = None
    hostname_matches: bool | None = None
    san_dns_names: list[str] = field(default_factory=list)
    public_key_algorithm: str = "unknown"
    public_key_bits: int = 0


@dataclass
class ProtocolProbe:
    version: str
    supported: bool
    negotiated_cipher: str | None = None
    error: str | None = None


@dataclass
class CipherSuiteAssessment:
    name: str
    protocol: str = "TLSv1.2"
    bits: int = 0
    classification: str = "strong"
    forward_secrecy: bool = False
    reason: str | None = None


@dataclass
class CertificateAssessment:
    subject: dict[str, Any] = field(default_factory=dict)
    issuer: dict[str, Any] = field(default_factory=dict)
    serial_number: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    valid_days: int = 0
    expired: bool = False
    near_expiry: bool = False
    self_signed: bool = False
    hostname_matches: bool | None = None
    san_dns_names: list[str] = field(default_factory=list)
    signature_algorithm: str = "unknown"
    weak_signature_algorithm: bool = False
    public_key_algorithm: str = "unknown"
    public_key_bits: int = 0
    weak_key: bool = False
    key_usage: list[str] = field(default_factory=list)
    extended_key_usage: list[str] = field(default_factory=list)
    crl_distribution_points: list[str] = field(default_factory=list)
    ocsp_urls: list[str] = field(default_factory=list)
    chain_length: int = 0
    chain_trusted: bool | None = None
    validation_error: str | None = None


@dataclass
class HSTSAssessment:
    checked: bool = False
    present: bool | None = None
    max_age: int | None = None
    include_subdomains: bool = False
    preload: bool = False
    weak: bool = False
    error: str | None = None
    raw_header: str | None = None


@dataclass
class TLSAssessment:
    host: str
    port: int
    negotiated: TLSInfo = field(default_factory=TLSInfo)
    protocols: list[ProtocolProbe] = field(default_factory=list)
    ciphers: list[CipherSuiteAssessment] = field(default_factory=list)
    certificate: CertificateAssessment = field(default_factory=CertificateAssessment)
    hsts: HSTSAssessment = field(default_factory=HSTSAssessment)
    limitations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def supported_protocols(self) -> list[str]:
        return [item.version for item in self.protocols if item.supported]


def assess_tls_security(hostname: str, port: int = 443, timeout: float | None = None, include_hsts: bool = True) -> TLSAssessment:
    timeout = timeout or settings.TLS_CONNECT_TIMEOUT_SECONDS
    assessment = TLSAssessment(host=hostname, port=port)

    negotiated, cert_bin, cert_dict = _negotiate_default(hostname, port, timeout)
    assessment.negotiated = negotiated
    if cert_bin:
        assessment.certificate = _parse_certificate(cert_bin, cert_dict, hostname)
        _copy_certificate_to_tls_info(assessment.negotiated, assessment.certificate)
    else:
        assessment.errors.append("No peer certificate was retrieved from the server.")

    assessment.protocols = [_probe_protocol(hostname, port, version, timeout) for version in ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")]
    assessment.ciphers = _enumerate_tls12_ciphers(hostname, port, timeout)
    if not assessment.ciphers:
        assessment.limitations.append("Cipher enumeration is limited by the local OpenSSL build or remote handshake policy.")

    if include_hsts:
        assessment.hsts = get_hsts_assessment(hostname, timeout=timeout)

    trusted, validation_error = _validate_trust(hostname, port, timeout)
    assessment.certificate.chain_trusted = trusted
    assessment.certificate.validation_error = validation_error
    assessment.negotiated.chain_trusted = trusted
    assessment.negotiated.hostname_matches = assessment.certificate.hostname_matches

    return assessment


def get_tls_info(hostname: str, port: int = 443, timeout: float = 10.0) -> TLSInfo:
    return assess_tls_security(hostname, port, timeout=timeout, include_hsts=False).negotiated


def _negotiate_default(hostname: str, port: int, timeout: float) -> tuple[TLSInfo, bytes | None, dict[str, Any]]:
    info = TLSInfo()
    cert_bin = None
    cert_dict: dict[str, Any] = {}
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
                    info.forward_secrecy = any(token in info.cipher_suite.upper() for token in FS_TOKENS) or info.tls_version == "TLSv1.3"
                cert_bin = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert() or {}
    except Exception as exc:
        logger.warning("TLS negotiation failed for %s:%s: %s", hostname, port, exc)
    return info, cert_bin, cert_dict


def _probe_protocol(hostname: str, port: int, version: str, timeout: float) -> ProtocolProbe:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = TLS_VERSION_MAP[version]
    ctx.maximum_version = TLS_VERSION_MAP[version]
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                return ProtocolProbe(version=version, supported=True, negotiated_cipher=cipher[0] if cipher else None)
    except Exception as exc:
        return ProtocolProbe(version=version, supported=False, error=str(exc))


def _enumerate_tls12_ciphers(hostname: str, port: int, timeout: float) -> list[CipherSuiteAssessment]:
    base_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cipher_names = sorted({item["name"] for item in base_context.get_ciphers() if item.get("protocol") != "TLSv1.3"})
    accepted: dict[str, CipherSuiteAssessment] = {}
    for cipher_name in cipher_names:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.set_ciphers(cipher_name)
        except ssl.SSLError:
            continue
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        name = cipher[0]
                        accepted[name] = _classify_cipher(name, bits=cipher[2] if len(cipher) > 2 else 0)
        except Exception:
            continue
    return sorted(accepted.values(), key=lambda item: item.name)


def _classify_cipher(name: str, bits: int = 0, protocol: str = "TLSv1.2") -> CipherSuiteAssessment:
    upper = name.upper()
    forward_secrecy = any(token in upper for token in FS_TOKENS)
    if any(token in upper for token in WEAK_CIPHER_TOKENS):
        return CipherSuiteAssessment(name=name, protocol=protocol, bits=bits, classification="insecure", forward_secrecy=forward_secrecy, reason="Contains deprecated or insecure cipher primitive.")
    if any(token in upper for token in ACCEPTABLE_CIPHER_TOKENS):
        return CipherSuiteAssessment(name=name, protocol=protocol, bits=bits, classification="acceptable", forward_secrecy=forward_secrecy, reason="CBC suites require careful protocol and implementation controls.")
    if not forward_secrecy and not upper.startswith("TLS_AES_"):
        return CipherSuiteAssessment(name=name, protocol=protocol, bits=bits, classification="weak", forward_secrecy=False, reason="Cipher suite does not provide forward secrecy.")
    return CipherSuiteAssessment(name=name, protocol=protocol, bits=bits, classification="strong", forward_secrecy=forward_secrecy)


def _parse_certificate(cert_bin: bytes, cert_dict: dict[str, Any], hostname: str) -> CertificateAssessment:
    cert = x509.load_der_x509_certificate(cert_bin)
    now = datetime.now(timezone.utc)
    not_before = _ensure_aware(cert.not_valid_before)
    not_after = _ensure_aware(cert.not_valid_after)
    public_key = cert.public_key()
    algorithm, bits = _public_key_info(public_key)
    san_dns_names = _dns_names(cert)
    hostname_matches = _hostname_matches(hostname, san_dns_names, cert.subject)
    signature = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else cert.signature_algorithm_oid._name
    weak_signature = signature.lower() in {"md5", "sha1", "md5-sha1"} or "sha1" in signature.lower() or "md5" in signature.lower()

    assessment = CertificateAssessment(
        subject=_name_to_dict(cert.subject),
        issuer=_name_to_dict(cert.issuer),
        serial_number=hex(cert.serial_number),
        not_before=not_before,
        not_after=not_after,
        valid_days=(not_after - now).days,
        expired=not_after < now,
        near_expiry=0 <= (not_after - now).days <= settings.TLS_NEAR_EXPIRY_DAYS,
        self_signed=cert.subject == cert.issuer,
        hostname_matches=hostname_matches,
        san_dns_names=san_dns_names,
        signature_algorithm=signature,
        weak_signature_algorithm=weak_signature,
        public_key_algorithm=algorithm,
        public_key_bits=bits,
        weak_key=_weak_key(algorithm, bits),
        key_usage=_key_usage(cert),
        extended_key_usage=_extended_key_usage(cert),
        crl_distribution_points=_crl_distribution_points(cert),
        ocsp_urls=_ocsp_urls(cert),
        chain_length=1,
    )

    if cert_dict:
        assessment.subject = _parse_cert_dn(cert_dict.get("subject", ())) or assessment.subject
        assessment.issuer = _parse_cert_dn(cert_dict.get("issuer", ())) or assessment.issuer
    return assessment


def _copy_certificate_to_tls_info(info: TLSInfo, cert: CertificateAssessment) -> None:
    info.cert_subject = cert.subject
    info.cert_issuer = cert.issuer
    info.cert_not_before = cert.not_before
    info.cert_not_after = cert.not_after
    info.cert_valid_days = cert.valid_days
    info.cert_sig_algorithm = cert.signature_algorithm
    info.self_signed = cert.self_signed
    info.cert_expired = cert.expired
    info.hostname_matches = cert.hostname_matches
    info.san_dns_names = cert.san_dns_names
    info.public_key_algorithm = cert.public_key_algorithm
    info.public_key_bits = cert.public_key_bits
    info.forward_secrecy = any(token in (info.cipher_suite or "").upper() for token in FS_TOKENS) or (info.tls_version == "TLSv1.3")


def _validate_trust(hostname: str, port: int, timeout: float) -> tuple[bool | None, str | None]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True, None
    except ssl.SSLCertVerificationError as exc:
        return False, str(exc)
    except Exception as exc:
        return None, str(exc)


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _name_to_dict(name: x509.Name) -> dict[str, str]:
    return {attribute.oid._name: attribute.value for attribute in name}


def _parse_cert_dn(dn_tuple) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for rdn in dn_tuple:
        for attr in rdn:
            result[attr[0]] = attr[1]
    return result


def _dns_names(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        return list(san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return []


def _hostname_matches(hostname: str, dns_names: list[str], subject: x509.Name) -> bool:
    names = dns_names or [attribute.value for attribute in subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    return any(_match_dns_name(hostname, pattern) for pattern in names)


def _match_dns_name(hostname: str, pattern: str) -> bool:
    hostname = hostname.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return hostname.endswith(pattern[1:]) and hostname.count(".") == pattern.count(".")
    return hostname == pattern


def _public_key_info(public_key: Any) -> tuple[str, int]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"ECDSA-{public_key.curve.name}", public_key.key_size
    return public_key.__class__.__name__, getattr(public_key, "key_size", 0)


def _weak_key(algorithm: str, bits: int) -> bool:
    if algorithm in {"RSA", "DSA"}:
        return bits < settings.TLS_MIN_RSA_BITS
    if algorithm.startswith("ECDSA"):
        return bits < settings.TLS_MIN_EC_BITS
    return False


def _key_usage(cert: x509.Certificate) -> list[str]:
    try:
        usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return []
    names = []
    for attr in ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign"):
        if getattr(usage, attr):
            names.append(attr)
    return names


def _extended_key_usage(cert: x509.Certificate) -> list[str]:
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound:
        return []
    mapping = {ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth", ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth"}
    return [mapping.get(oid, oid.dotted_string) for oid in eku]


def _crl_distribution_points(cert: x509.Certificate) -> list[str]:
    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
    except x509.ExtensionNotFound:
        return []
    urls = []
    for point in extension:
        for name in point.full_name or []:
            if isinstance(name, x509.UniformResourceIdentifier):
                urls.append(name.value)
    return urls


def _ocsp_urls(cert: x509.Certificate) -> list[str]:
    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return []
    urls = []
    for item in extension:
        if item.access_method == AuthorityInformationAccessOID.OCSP and isinstance(item.access_location, x509.UniformResourceIdentifier):
            urls.append(item.access_location.value)
    return urls


def get_hsts_assessment(hostname: str, timeout: float | None = None) -> HSTSAssessment:
    timeout = timeout or settings.TLS_CONNECT_TIMEOUT_SECONDS
    result = HSTSAssessment(checked=True)
    try:
        with create_sync_client(timeout=timeout) as client:
            response = request_with_retry_sync(client, "GET", f"https://{hostname}")
        if response is None:
            result.present = None
            result.error = "No HTTP response received while checking HSTS."
            return result
        header = response.headers.get("strict-transport-security")
        result.raw_header = header
        result.present = bool(header)
        if not header:
            return result
        directives = _parse_hsts(header)
        result.max_age = directives.get("max-age")
        result.include_subdomains = "includesubdomains" in directives
        result.preload = "preload" in directives
        result.weak = (result.max_age or 0) < settings.TLS_HSTS_MIN_AGE_SECONDS
    except Exception as exc:
        result.present = None
        result.error = str(exc)
    return result


def check_hsts(hostname: str) -> bool | None:
    return get_hsts_assessment(hostname).present


def _parse_hsts(header: str) -> dict[str, Any]:
    directives: dict[str, Any] = {}
    for part in header.split(";"):
        key, _, value = part.strip().partition("=")
        normalized = key.lower()
        if normalized == "max-age":
            try:
                directives[normalized] = int(value)
            except ValueError:
                directives[normalized] = 0
        elif normalized:
            directives[normalized] = True
    return directives
