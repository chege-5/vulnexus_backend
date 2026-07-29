"""Bounded SSLyze enrichment for admitted public URL targets.

The SSLyze Python API is synchronous, so it is always run in a worker thread.
Only compact facts are returned: SSLyze result objects can include certificates,
tracebacks, and byte values that must not be persisted verbatim.
"""
from __future__ import annotations

import asyncio
import multiprocessing
from queue import Empty
from typing import Any
from urllib.parse import urlparse

from app.config import settings
from app.services.models.pipeline import RawFinding, ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner
from app.utils.logger import get_logger
from app.utils.redaction import redact_data, redact_text

logger = get_logger(__name__)


_CIPHER_COMMANDS = (
    "ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites", "tls_1_0_cipher_suites",
    "tls_1_1_cipher_suites", "tls_1_2_cipher_suites", "tls_1_3_cipher_suites",
)
_DEPRECATED_COMMANDS = {"ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites", "tls_1_0_cipher_suites", "tls_1_1_cipher_suites"}
_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "ANON", "MD5")
_WEAK_CURVE_TOKENS = ("SECP160", "SECP192", "PRIME192", "SECT163", "SECT193")


class SSLyzeProcessError(RuntimeError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


def _sslyze_process_worker(hostname: str, port: int, network_timeout: int, result_queue) -> None:
    """Process entrypoint: only safe, compact data crosses the boundary."""
    try:
        result_queue.put({"status": "success", "snapshot": SSLyzeScanner()._run_scan(hostname, port, network_timeout)})
    except ImportError:
        result_queue.put({"status": "error", "category": "dependency_unavailable"})
    except Exception as exc:
        # Do not return raw SSLyze errors: certificate bodies and tracebacks
        # can be surprisingly large or sensitive.
        result_queue.put({"status": "error", "category": f"worker_{type(exc).__name__.lower()[:64]}"})


class SSLyzeScanner(TargetScanner):
    name = "sslyze"
    supported_kinds = {"url"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        if not settings.SSLYZE_ENABLED:
            return ScannerResult(metadata={"provider_statuses": [self._status("disabled")]})

        parsed = urlparse(target.value)
        hostname = parsed.hostname
        if not hostname:
            return ScannerResult(metadata={"provider_statuses": [self._status("skipped", reason="missing_hostname")]})
        port = parsed.port or 443
        total_timeout = float(settings.SSLYZE_TIMEOUT_SECONDS)
        # SSLyze's network_timeout covers the underlying socket operations
        # (connection and reads). With retries disabled, neither can consume
        # more than this small bounded slice of the overall deadline.
        network_timeout = max(1, min(5, int(total_timeout)))
        try:
            snapshot = await self._run_scan_in_process(hostname, port, network_timeout, total_timeout)
        except asyncio.TimeoutError:
            logger.warning("SSLyze timed out host=%s port=%s", hostname, port)
            return ScannerResult(metadata={"provider_statuses": [self._status("skipped", reason="overall_timeout")]})
        except SSLyzeProcessError as exc:
            if exc.category == "dependency_unavailable":
                logger.error("SSLyze dependency is unavailable; install the pinned requirements")
                return ScannerResult(metadata={"provider_statuses": [self._status("skipped", reason=exc.category)]})
            logger.warning("SSLyze enrichment failed host=%s port=%s category=%s", hostname, port, exc.category)
            return ScannerResult(metadata={"provider_statuses": [self._status("skipped", reason="scan_failed", error_category=exc.category)]})
        except ImportError:
            logger.error("SSLyze dependency is unavailable; install the pinned requirements")
            return ScannerResult(metadata={"provider_statuses": [self._status("skipped", reason="dependency_unavailable")]})
        except Exception as exc:
            logger.warning("SSLyze enrichment failed host=%s port=%s error=%s", hostname, port, redact_text(exc)[:160])
            return ScannerResult(metadata={"provider_statuses": [self._status("skipped", reason="scan_failed")]})

        findings = self._build_findings(snapshot, target.value)
        metadata = {
            "provider": "sslyze",
            "host": hostname,
            "port": port,
            "checks_completed": snapshot.get("checks_completed", []),
            "provider_statuses": [self._status("success", checks=len(snapshot.get("checks_completed", [])))],
        }
        return ScannerResult(findings=findings, metadata=redact_data(metadata))

    async def _run_scan_in_process(self, hostname: str, port: int, network_timeout: int, total_timeout: float) -> dict[str, Any]:
        """Run SSLyze behind a killable boundary, never a cancellable thread."""
        context = multiprocessing.get_context("spawn")
        result_queue = context.Queue(maxsize=1)
        process = context.Process(
            target=_sslyze_process_worker,
            args=(hostname, port, network_timeout, result_queue),
            daemon=True,
        )
        process.start()
        deadline = asyncio.get_running_loop().time() + total_timeout
        try:
            while True:
                try:
                    result = result_queue.get_nowait()
                    if result.get("status") == "success":
                        return result["snapshot"]
                    raise SSLyzeProcessError(str(result.get("category") or "worker_failed"))
                except Empty:
                    if not process.is_alive():
                        raise SSLyzeProcessError("worker_exited_without_result")
                    if asyncio.get_running_loop().time() >= deadline:
                        raise asyncio.TimeoutError
                    await asyncio.sleep(0.05)
        finally:
            await asyncio.to_thread(self._terminate_process, process)
            result_queue.close()
            result_queue.join_thread()

    @staticmethod
    def _terminate_process(process) -> None:
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
        if process.is_alive():
            process.kill()
            process.join(timeout=2)

    def _run_scan(self, hostname: str, port: int, network_timeout: int) -> dict[str, Any]:
        # Imported here so a disabled integration never prevents the worker
        # from starting, while production always uses SSLyze's Python API.
        from sslyze import ScanCommand, Scanner, ServerNetworkConfiguration, ServerNetworkLocation, ServerScanRequest

        command_names = {
            "SSL_2_0_CIPHER_SUITES", "SSL_3_0_CIPHER_SUITES", "TLS_1_0_CIPHER_SUITES",
            "TLS_1_1_CIPHER_SUITES", "TLS_1_2_CIPHER_SUITES", "TLS_1_3_CIPHER_SUITES",
            "HEARTBLEED", "ROBOT", "OPENSSL_CCS_INJECTION", "SESSION_RENEGOTIATION",
            "ELLIPTIC_CURVES", "CERTIFICATE_INFO",
        }
        commands = {getattr(ScanCommand, name) for name in command_names if hasattr(ScanCommand, name)}
        request = ServerScanRequest(
            server_location=ServerNetworkLocation(hostname=hostname, port=port),
            network_configuration=ServerNetworkConfiguration(
                tls_server_name_indication=hostname,
                network_timeout=network_timeout,
                network_max_retries=0,
            ),
            scan_commands=commands,
        )
        scanner = Scanner(per_server_concurrent_connections_limit=2, concurrent_server_scans_limit=1)
        scanner.queue_scans([request])
        result = next(iter(scanner.get_results()), None)
        if result is None or getattr(result, "scan_result", None) is None:
            raise RuntimeError("SSLyze did not return a completed scan result")
        return self._normalize_result(result.scan_result)

    def _normalize_result(self, scan_result: Any) -> dict[str, Any]:
        snapshot: dict[str, Any] = {
            "deprecated_protocols": [], "weak_ciphers": [], "weak_curves": [],
            "heartbleed": False, "robot": None, "openssl_ccs": False,
            "insecure_renegotiation": False, "certificate_chain_problem": False,
            "checks_completed": [],
        }
        for command in _CIPHER_COMMANDS:
            result = self._completed_result(getattr(scan_result, command, None))
            if result is None:
                continue
            snapshot["checks_completed"].append(command)
            accepted = list(getattr(result, "accepted_cipher_suites", None) or [])
            version = self._enum_text(getattr(result, "tls_version_used", command))
            if command in _DEPRECATED_COMMANDS and accepted:
                snapshot["deprecated_protocols"].append(version)
            for item in accepted:
                cipher = getattr(item, "cipher_suite", item)
                name = str(getattr(cipher, "name", cipher))
                anonymous = bool(getattr(cipher, "is_anonymous", False))
                if anonymous or any(token in name.upper() for token in _WEAK_CIPHER_TOKENS):
                    snapshot["weak_ciphers"].append(name)

        heartbleed = self._completed_result(getattr(scan_result, "heartbleed", None))
        if heartbleed is not None:
            snapshot["checks_completed"].append("heartbleed")
            snapshot["heartbleed"] = bool(getattr(heartbleed, "is_vulnerable_to_heartbleed", False))
        robot = self._completed_result(getattr(scan_result, "robot", None))
        if robot is not None:
            snapshot["checks_completed"].append("robot")
            snapshot["robot"] = self._enum_text(getattr(robot, "robot_result", None))
        ccs = self._completed_result(getattr(scan_result, "openssl_ccs_injection", None))
        if ccs is not None:
            snapshot["checks_completed"].append("openssl_ccs_injection")
            snapshot["openssl_ccs"] = bool(getattr(ccs, "is_vulnerable_to_ccs_injection", False))
        renegotiation = self._completed_result(getattr(scan_result, "session_renegotiation", None))
        if renegotiation is not None:
            snapshot["checks_completed"].append("session_renegotiation")
            snapshot["insecure_renegotiation"] = (
                getattr(renegotiation, "supports_secure_renegotiation", True) is False
                or bool(getattr(renegotiation, "is_vulnerable_to_client_renegotiation_dos", False))
            )
        curves = self._completed_result(getattr(scan_result, "elliptic_curves", None))
        if curves is not None:
            snapshot["checks_completed"].append("elliptic_curves")
            for curve in list(getattr(curves, "supported_curves", None) or []):
                name = str(getattr(curve, "name", curve))
                if any(token in name.upper() for token in _WEAK_CURVE_TOKENS):
                    snapshot["weak_curves"].append(name)
        certificate = self._completed_result(getattr(scan_result, "certificate_info", None))
        if certificate is not None:
            snapshot["checks_completed"].append("certificate_info")
            deployments = list(getattr(certificate, "certificate_deployments", None) or [])
            for deployment in deployments:
                invalid_order = getattr(deployment, "received_chain_has_valid_order", None) is False
                validations = list(getattr(deployment, "path_validation_results", None) or [])
                all_failed = bool(validations) and not any(bool(getattr(item, "was_validation_successful", False)) for item in validations)
                if invalid_order or all_failed:
                    snapshot["certificate_chain_problem"] = True
                    break
        for key in ("deprecated_protocols", "weak_ciphers", "weak_curves", "checks_completed"):
            snapshot[key] = sorted(set(snapshot[key]))
        return snapshot

    @staticmethod
    def _completed_result(attempt: Any) -> Any | None:
        result = getattr(attempt, "result", None)
        return result if result is not None else None

    @staticmethod
    def _enum_text(value: Any) -> str:
        return str(getattr(value, "name", getattr(value, "value", value)) or "unknown")

    def _build_findings(self, snapshot: dict[str, Any], target_value: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        checks = list(snapshot.get("checks_completed") or [])
        if snapshot.get("deprecated_protocols"):
            findings.append(self._finding_for(
                "DAST_SSLYZE_DEPRECATED_TLS", "Deprecated TLS versions supported",
                "SSLyze confirmed that the target accepts deprecated TLS protocol versions.", "High",
                {"deprecated_protocols": snapshot["deprecated_protocols"], "checks": checks}, target_value,
                "Disable SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1; require TLS 1.2 or newer.", 0.98,
            ))
        if snapshot.get("weak_ciphers"):
            findings.append(self._finding_for(
                "DAST_SSLYZE_WEAK_CIPHERS", "Weak TLS cipher suites accepted",
                "SSLyze confirmed that the target accepts weak or anonymous cipher suites.", "High",
                {"weak_ciphers": snapshot["weak_ciphers"][:10], "checks": checks}, target_value,
                "Disable weak, export, anonymous, RC4, DES/3DES, NULL, and MD5 cipher suites; use modern AEAD suites.", 0.96,
            ))
        if snapshot.get("heartbleed"):
            findings.append(self._finding_for("DAST_SSLYZE_HEARTBLEED", "Heartbleed vulnerability detected", "SSLyze confirmed Heartbleed behavior on the TLS service.", "Critical", {"heartbleed": True}, target_value, "Patch the affected TLS implementation immediately and replace potentially exposed private keys and certificates.", 0.99))
        robot = str(snapshot.get("robot") or "")
        if "VULNERABLE" in robot and "NOT_VULNERABLE" not in robot:
            findings.append(self._finding_for("DAST_SSLYZE_ROBOT", "ROBOT TLS oracle vulnerability detected", "SSLyze reported a vulnerable RSA padding oracle condition.", "Critical" if "STRONG" in robot else "High", {"robot_result": robot}, target_value, "Disable RSA key-exchange cipher suites and update the TLS stack; prefer ECDHE-based cipher suites.", 0.98))
        if snapshot.get("openssl_ccs"):
            findings.append(self._finding_for("DAST_SSLYZE_OPENSSL_CCS", "OpenSSL CCS injection vulnerability detected", "SSLyze confirmed the OpenSSL ChangeCipherSpec injection condition.", "High", {"openssl_ccs_injection": True}, target_value, "Upgrade OpenSSL or the TLS library to a version patched for CVE-2014-0224.", 0.99))
        if snapshot.get("insecure_renegotiation"):
            findings.append(self._finding_for("DAST_SSLYZE_INSECURE_RENEGOTIATION", "Insecure TLS renegotiation supported", "SSLyze reported insecure renegotiation or client-initiated renegotiation DoS exposure.", "Medium", {"insecure_renegotiation": True}, target_value, "Enable RFC 5746 secure renegotiation and disable unsafe client-initiated renegotiation where possible.", 0.94))
        if snapshot.get("weak_curves"):
            findings.append(self._finding_for("DAST_SSLYZE_WEAK_EC_CURVES", "Weak elliptic curves accepted", "SSLyze confirmed support for elliptic curves below the configured security baseline.", "Medium", {"weak_curves": snapshot["weak_curves"][:10]}, target_value, "Disable legacy small elliptic curves and retain modern curves such as X25519 and secp256r1 or stronger.", 0.93))
        if snapshot.get("certificate_chain_problem"):
            findings.append(self._finding_for("DAST_SSLYZE_CERTIFICATE_CHAIN", "TLS certificate chain validation problem", "SSLyze reported an invalid certificate-chain order or no successful trust-store validation.", "High", {"certificate_chain_problem": True}, target_value, "Deploy the complete certificate chain in the correct order from a publicly trusted issuer and verify hostname coverage.", 0.96))
        return findings

    def _finding_for(self, rule_id: str, title: str, description: str, severity: str, evidence: dict[str, Any], target_value: str, remediation: str, confidence: float) -> RawFinding:
        return self._finding(
            finding_type="tls",
            title=title,
            description=description,
            severity=severity,
            evidence=redact_data({"source": "SSLyze", "category": "TLS security", **evidence}),
            location=target_value,
            confidence=confidence,
            confidence_label="confirmed",
            raw_data={"rule_id": rule_id, "source_metadata": {"provider": "SSLyze", "api": "python", "raw_response_omitted": True}},
            target=target_value,
            tags=["dast", "tls", "sslyze"],
            remediation=remediation,
            references=["https://nabla-c0d3.github.io/sslyze/documentation/"],
        )

    @staticmethod
    def _status(status: str, **details: Any) -> dict[str, Any]:
        return {"provider": "sslyze", "status": status, "success": status == "success", **details}
