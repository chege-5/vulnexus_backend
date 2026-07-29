from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from app.services.models.pipeline import RawFinding
from app.services.orchestration.scan_orchestrator import ScanOrchestrator
from app.services.scanners.crtsh import CrtShScanner
from app.services.scanners.sslyze import SSLyzeScanner


def test_sslyze_normalizes_high_value_results_to_stable_redacted_findings():
    scanner = SSLyzeScanner()
    findings = scanner._build_findings(
        {
            "deprecated_protocols": ["TLS_1_0"],
            "weak_ciphers": ["RC4-SHA"],
            "heartbleed": True,
            "robot": "VULNERABLE_STRONG_ORACLE",
            "openssl_ccs": True,
            "insecure_renegotiation": True,
            "weak_curves": ["secp192r1"],
            "certificate_chain_problem": True,
            "checks_completed": ["heartbleed", "robot"],
        },
        "https://example.com",
    )

    rule_ids = {finding.raw_data["rule_id"] for finding in findings}
    assert {
        "DAST_SSLYZE_DEPRECATED_TLS", "DAST_SSLYZE_WEAK_CIPHERS", "DAST_SSLYZE_HEARTBLEED",
        "DAST_SSLYZE_ROBOT", "DAST_SSLYZE_OPENSSL_CCS", "DAST_SSLYZE_INSECURE_RENEGOTIATION",
        "DAST_SSLYZE_WEAK_EC_CURVES", "DAST_SSLYZE_CERTIFICATE_CHAIN",
    } <= rule_ids
    assert all(finding.remediation and finding.compliance_mapping for finding in findings)
    assert all(finding.raw_data["source_metadata"]["raw_response_omitted"] is True for finding in findings)
    assert all(finding.evidence["source"] == "SSLyze" for finding in findings)


def test_sslyze_result_normalizer_reads_python_api_result_shape_without_raw_objects():
    scanner = SSLyzeScanner()
    completed = lambda result: SimpleNamespace(result=result)
    result = SimpleNamespace(
        tls_1_0_cipher_suites=completed(SimpleNamespace(
            tls_version_used=SimpleNamespace(name="TLS_1_0"),
            accepted_cipher_suites=[SimpleNamespace(cipher_suite=SimpleNamespace(name="RC4-SHA", is_anonymous=False))],
        )),
        heartbleed=completed(SimpleNamespace(is_vulnerable_to_heartbleed=True)),
        robot=completed(SimpleNamespace(robot_result=SimpleNamespace(name="VULNERABLE_WEAK_ORACLE"))),
        openssl_ccs_injection=completed(SimpleNamespace(is_vulnerable_to_ccs_injection=True)),
        session_renegotiation=completed(SimpleNamespace(supports_secure_renegotiation=False, is_vulnerable_to_client_renegotiation_dos=False)),
        elliptic_curves=completed(SimpleNamespace(supported_curves=[SimpleNamespace(name="secp192r1")])),
        certificate_info=completed(SimpleNamespace(certificate_deployments=[SimpleNamespace(
            received_chain_has_valid_order=False,
            path_validation_results=[],
        )])),
    )

    snapshot = scanner._normalize_result(result)
    assert snapshot["deprecated_protocols"] == ["TLS_1_0"]
    assert snapshot["weak_ciphers"] == ["RC4-SHA"]
    assert snapshot["heartbleed"] is True
    assert snapshot["certificate_chain_problem"] is True


def test_crtsh_keeps_only_matching_names_and_redacts_exposed_subdomains():
    scanner = CrtShScanner()
    intelligence = scanner._normalize(
        [
            {"id": 1, "issuer_ca_id": 7, "name_value": "www.example.com\ndev.example.com"},
            {"id": 2, "issuer_ca_id": 7, "name_value": "*.example.com"},
            {"id": 3, "issuer_ca_id": 7, "name_value": "other.example.net"},
        ],
        "example.com",
    )
    findings = scanner._build_findings(intelligence, "https://example.com")

    assert intelligence["certificate_count"] == 3
    assert intelligence["matching_name_count"] == 3
    assert all("dev.example.com" not in str(finding.evidence) for finding in findings)
    assert {finding.raw_data["rule_id"] for finding in findings} == {
        "DAST_CRTSH_CERTIFICATE_INVENTORY", "DAST_CRTSH_SENSITIVE_SUBDOMAIN",
    }
    assert all(finding.remediation and finding.compliance_mapping for finding in findings)


def test_url_pipeline_deduplicates_overlapping_tls_and_sslyze_findings():
    tls = [RawFinding(type="tls", title="Weak cipher", description="TLS scanner finding", raw_data={"rule_id": "WEAK_CIPHER_SUITE"})]
    sslyze = [
        RawFinding(type="tls", title="Weak cipher", description="SSLyze finding", raw_data={"rule_id": "DAST_SSLYZE_WEAK_CIPHERS"}),
        RawFinding(type="tls", title="Heartbleed", description="SSLyze finding", raw_data={"rule_id": "DAST_SSLYZE_HEARTBLEED"}),
    ]

    retained = ScanOrchestrator._deduplicate_sslyze_findings(sslyze, tls)
    assert [item.raw_data["rule_id"] for item in retained] == ["DAST_SSLYZE_HEARTBLEED"]


def test_sslyze_process_termination_escalates_to_kill_when_needed():
    class StuckProcess:
        def __init__(self):
            self.terminated = self.killed = False
            self.joins = []

        def is_alive(self):
            return not self.killed

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True

        def join(self, timeout):
            self.joins.append(timeout)

    process = StuckProcess()
    SSLyzeScanner._terminate_process(process)

    assert process.terminated is True
    assert process.killed is True
    assert process.joins == [2, 2]


def test_crtsh_timeout_status_includes_safe_category_and_exception_class():
    scanner = CrtShScanner()

    assert scanner._error_category(httpx.ReadTimeout("timed out")) == "timeout"
    status = scanner._status("skipped", reason="timeout", error="timeout", exception_class="ReadTimeout")
    assert status["error"] == "timeout"
    assert status["exception_class"] == "ReadTimeout"
