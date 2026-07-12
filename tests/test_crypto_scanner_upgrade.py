from __future__ import annotations

from app.services.file_scanner import scan_file_content
from app.services.scanners.tls import TLSScanner
from app.utils.tls_utils import CertificateAssessment, CipherSuiteAssessment, HSTSAssessment, ProtocolProbe, TLSAssessment, TLSInfo


def test_tls_scanner_separates_protocol_cipher_certificate_and_hsts_findings():
    assessment = TLSAssessment(
        host="example.com",
        port=443,
        negotiated=TLSInfo(tls_version="TLSv1.2", cipher_suite="ECDHE-RSA-AES128-GCM-SHA256", cipher_bits=128, forward_secrecy=True),
        protocols=[
            ProtocolProbe(version="TLSv1", supported=True, negotiated_cipher="AES128-SHA"),
            ProtocolProbe(version="TLSv1.2", supported=True, negotiated_cipher="ECDHE-RSA-AES128-GCM-SHA256"),
        ],
        ciphers=[
            CipherSuiteAssessment(name="DES-CBC3-SHA", bits=112, classification="insecure", forward_secrecy=False),
            CipherSuiteAssessment(name="ECDHE-RSA-AES128-GCM-SHA256", bits=128, classification="strong", forward_secrecy=True),
        ],
        certificate=CertificateAssessment(
            subject={"commonName": "example.com"},
            issuer={"commonName": "Example CA"},
            self_signed=False,
            hostname_matches=True,
            public_key_algorithm="RSA",
            public_key_bits=2048,
            chain_trusted=True,
        ),
        hsts=HSTSAssessment(checked=True, present=True, max_age=300, weak=True, raw_header="max-age=300"),
    )

    findings = TLSScanner()._build_findings(assessment, "https://example.com")
    rule_ids = {finding.raw_data["rule_id"] for finding in findings}

    assert "WEAK_TLS_VERSION" in rule_ids
    assert "WEAK_CIPHER_SUITE" in rule_ids
    assert "WEAK_HSTS" in rule_ids
    assert all(finding.evidence for finding in findings)
    assert all(finding.compliance_mapping for finding in findings)


def test_source_crypto_scanner_masks_hardcoded_secret_evidence():
    code = 'api_token = "abcdefghijklmnopqrstuvwxyz123456"\n'
    vulns, features = scan_file_content(code, "settings.py")

    hardcoded = next(vuln for vuln in vulns if vuln.rule_id == "HARDCODED_KEY")

    assert features.hardcoded_key is True
    assert "abcdefghijklmnopqrstuvwxyz123456" not in str(hardcoded.evidence)
    assert "api_token" in str(hardcoded.evidence)
    assert "[REDACTED]" in str(hardcoded.evidence)
    assert hardcoded.confidence_label == "confirmed"


def test_source_crypto_scanner_downgrades_checksum_md5_context():
    code = "checksum = hashlib.md5(payload).hexdigest()\n"
    vulns, features = scan_file_content(code, "checksum.py")

    md5 = next(vuln for vuln in vulns if vuln.rule_id == "WEAK_HASH_MD5")

    assert features.uses_md5 is True
    assert md5.severity == "Low"
    assert md5.confidence_label == "informational"
