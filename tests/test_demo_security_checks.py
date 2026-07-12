import json
from pathlib import Path

from app.models.pydantic_models import RuleVulnerability
from app.services.file_scanner import scan_file_content
from app.services.report_generator import build_report_payload, prepare_findings_for_report
from app.services.scanners.headers import HeaderScanner
from app.services.web_scanner import _analyze_tls
from app.utils.tls_utils import TLSInfo


FIXTURES = Path(__file__).parent / "fixtures" / "security_checks"


def _scan_fixture(name: str) -> list[RuleVulnerability]:
    path = FIXTURES / name
    findings, _ = scan_file_content(path.read_text(encoding="utf-8"), str(path))
    return findings


def _assert_demo_finding(finding, category: str):
    assert finding.severity
    assert finding.evidence
    assert finding.remediation or getattr(finding, "recommendation", None)
    assert finding.category == category


def test_weak_hashing_fixture_produces_finding():
    findings = _scan_fixture("weak_hashing_sample.py")
    weak_hash = next(f for f in findings if f.category == "Weak hashing")
    _assert_demo_finding(weak_hash, "Weak hashing")


def test_hardcoded_keys_fixture_produces_masked_finding():
    findings = _scan_fixture("hardcoded_keys_sample.env")
    secret = next(f for f in findings if f.category == "Hardcoded keys")
    _assert_demo_finding(secret, "Hardcoded keys")
    evidence = json.dumps(secret.evidence)
    assert "AKIAIOSFODNN7EXAMPLE" not in evidence
    assert "demo_password" not in evidence
    assert "..." in evidence


def test_insecure_randomness_fixture_produces_finding():
    findings = _scan_fixture("insecure_randomness_sample.js")
    random_finding = next(f for f in findings if f.category == "Insecure randomness")
    _assert_demo_finding(random_finding, "Insecure randomness")


def test_poor_key_management_fixture_produces_masked_finding():
    findings = _scan_fixture("poor_key_management_sample.yml")
    key_mgmt = next(f for f in findings if f.category == "Poor key management")
    _assert_demo_finding(key_mgmt, "Poor key management")
    evidence = json.dumps(key_mgmt.evidence)
    assert "0123456789abcdef0123456789abcdef" not in evidence
    assert "static-demo-salt" not in evidence


def test_tls_misconfiguration_produces_finding():
    tls = TLSInfo(tls_version="TLSv1", cipher_suite="DES-CBC3-SHA", cipher_bits=112, forward_secrecy=False)
    findings = _analyze_tls(tls, False, "https://demo.local")
    tls_finding = findings[0]
    assert tls_finding.rule_id in {"WEAK_TLS_VERSION", "WEAK_CIPHER_SUITE", "NO_HSTS", "NO_FORWARD_SECRECY"}
    assert tls_finding.severity
    assert tls_finding.description


def test_missing_headers_fixture_produces_finding():
    sample = json.loads((FIXTURES / "missing_headers_demo.json").read_text(encoding="utf-8"))
    findings = HeaderScanner()._analyze_headers(sample["headers"], sample["url"], sample["status_code"])
    assert findings
    header_finding = findings[0]
    assert header_finding.evidence["category"] == "Missing secure headers"
    assert header_finding.severity
    assert header_finding.remediation
    assert header_finding.evidence


def test_weak_crypto_modes_fixture_produces_finding():
    findings = _scan_fixture("weak_crypto_modes_sample.py")
    weak_mode = next(f for f in findings if f.category == "Weak cryptographic modes")
    _assert_demo_finding(weak_mode, "Weak cryptographic modes")


def test_demo_report_payload_displays_all_seven_categories():
    file_findings = []
    for name in [
        "weak_hashing_sample.py",
        "hardcoded_keys_sample.env",
        "insecure_randomness_sample.js",
        "poor_key_management_sample.yml",
        "weak_crypto_modes_sample.py",
    ]:
        file_findings.extend(f.model_dump() for f in _scan_fixture(name))

    tls = TLSInfo(tls_version="TLSv1", cipher_suite="DES-CBC3-SHA", cipher_bits=112, forward_secrecy=False)
    file_findings.extend(f.model_dump() for f in _analyze_tls(tls, False, "https://demo.local"))

    sample = json.loads((FIXTURES / "missing_headers_demo.json").read_text(encoding="utf-8"))
    file_findings.extend(f.model_dump() for f in HeaderScanner()._analyze_headers(sample["headers"], sample["url"], sample["status_code"]))

    prepared = prepare_findings_for_report(file_findings)
    categories = {finding["display_category"] for finding in prepared}
    assert {
        "Weak hashing",
        "Hardcoded keys",
        "Insecure randomness",
        "Poor key management",
        "TLS misconfiguration",
        "Missing secure headers",
        "Weak cryptographic modes",
    }.issubset(categories)

    payload = build_report_payload(
        scan_id="00000000-0000-0000-0000-000000000001",
        target="demo security checks",
        scan_type="demo",
        overall_score=88,
        vulnerabilities=file_findings,
        cve_details=[],
    )
    assert len(payload["vulnerabilities"]) >= 7
    assert all(finding["display_title"] for finding in payload["vulnerabilities"])
    assert all(finding["display_evidence"] for finding in payload["vulnerabilities"])
