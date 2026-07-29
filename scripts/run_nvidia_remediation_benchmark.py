"""Run the controlled NVIDIA-only, eight-finding remediation benchmark.

This script does not write to the database or start a scan.  It exercises the
same sanitized payload builder and provider contract used by completed scans,
then emits machine-readable pass/fail metrics for the model decision.
"""
from __future__ import annotations

import asyncio
import json
import sys
from statistics import mean
from typing import Any

from app.config import settings
from app.services.ai.explanations import AIExplanationService, AIExplanationUnavailable, AIRemediationRetryable


CONTROLLED_FINDINGS: list[dict[str, Any]] = [
    {
        "id": f"controlled-{index}",
        "rule_id": rule_id,
        "title": title,
        "category": category,
        "severity": severity,
        "file_path": file_path,
        "line_number": index * 10,
        "evidence": {"language": "python", "signal": signal},
        "remediation": remediation,
    }
    for index, (rule_id, title, category, severity, file_path, signal, remediation) in enumerate(
        [
            ("SAST_PY_HARDCODED_SECRET", "Hard-coded credential", "Secrets", "Critical", "src/settings.py", "credential literal", "Move the credential to a managed secret store and rotate it."),
            ("SAST_PY_SQL_INJECTION", "Unsafe SQL construction", "Injection", "High", "src/users.py", "string-built query", "Use parameterized queries and validate input."),
            ("SAST_PY_JINJA_TEMPLATE_UNSAFE", "Direct template construction", "Injection", "High", "src/templates.py", "untrusted template source", "Use a controlled Jinja environment with autoescape."),
            ("WEAK_TLS_VERSION", "Obsolete TLS version", "Transport", "High", "infra/tls.conf", "TLS 1.0 enabled", "Require TLS 1.2 or newer."),
            ("MISSING_HSTS", "HSTS header missing", "HTTP headers", "Medium", "infra/headers.conf", "Strict-Transport-Security absent", "Set HSTS after confirming HTTPS readiness."),
            ("SAST_PY_INSECURE_HASH", "Weak password hash", "Cryptography", "Medium", "src/auth.py", "legacy digest", "Use a modern password hashing algorithm with a unique salt."),
            ("MISSING_SECURE_COOKIE", "Sensitive cookie lacks Secure", "Session security", "Medium", "src/session.py", "cookie flag absent", "Set Secure, HttpOnly, and an appropriate SameSite policy."),
            ("SAST_PY_INSECURE_RANDOM", "Predictable random source", "Cryptography", "Low", "src/tokens.py", "non-cryptographic random source", "Use a cryptographically secure random generator for tokens."),
        ],
        start=1,
    )
]


def _require_nvidia_only() -> None:
    if settings.AI_PRIMARY_PROVIDER.strip().lower() != "nvidia" or settings.AI_FALLBACK_PROVIDER.strip().lower() != "disabled":
        raise SystemExit("Benchmark requires AI_PRIMARY_PROVIDER=nvidia and AI_FALLBACK_PROVIDER=disabled.")
    if not settings.NVIDIA_API_KEY:
        raise SystemExit("Benchmark requires NVIDIA_API_KEY.")
    if not 1 <= settings.AI_REMEDIATION_BATCH_SIZE <= 3:
        raise SystemExit("AI_REMEDIATION_BATCH_SIZE must be between 1 and 3.")


async def run() -> dict[str, Any]:
    _require_nvidia_only()
    service = AIExplanationService()
    attempts: list[dict[str, Any]] = []
    valid_responses = 0
    retries = 0

    for offset in range(0, len(CONTROLLED_FINDINGS), settings.AI_REMEDIATION_BATCH_SIZE):
        batch = CONTROLLED_FINDINGS[offset:offset + settings.AI_REMEDIATION_BATCH_SIZE]
        payload = service.payload_builder.build(
            scan_id="controlled-nvidia-8",
            scan_type="controlled",
            target="controlled-remediation-fixture",
            findings=batch,
        )
        for retry_index in range(settings.AI_REMEDIATION_RETRY_COUNT + 1):
            try:
                result = await service.remediate(payload=payload)
                attempts.extend(result.attempts)
                if result.unresolved_finding_ids or len(result.findings) != len(batch):
                    break
                valid_responses += len(result.findings)
                break
            except AIRemediationRetryable as exc:
                attempts.extend(exc.attempts)
                if retry_index >= settings.AI_REMEDIATION_RETRY_COUNT:
                    break
                retries += 1
                await asyncio.sleep(settings.AI_REMEDIATION_RETRY_BACKOFF_SECONDS * (2 ** retry_index))
            except AIExplanationUnavailable as exc:
                attempts.extend(exc.attempts)
                break

    nvidia_attempts = [attempt for attempt in attempts if attempt["provider"] == "nvidia"]
    latencies = [attempt["latency_ms"] for attempt in nvidia_attempts if isinstance(attempt.get("latency_ms"), int)]
    malformed = sum(attempt.get("invalid_count", 0) for attempt in nvidia_attempts)
    timeout_ms = round(settings.AI_REMEDIATION_BATCH_TIMEOUT_SECONDS * 1000)
    all_within_timeout = bool(latencies) and all(latency <= timeout_ms for latency in latencies)
    passed = valid_responses == len(CONTROLLED_FINDINGS) and malformed == 0 and all_within_timeout
    return {
        "provider": "nvidia",
        "model": settings.NVIDIA_MODEL,
        "eligible_findings": len(CONTROLLED_FINDINGS),
        "valid_responses": valid_responses,
        "valid_responses_per_eligible": f"{valid_responses}/{len(CONTROLLED_FINDINGS)}",
        "average_latency_ms": round(mean(latencies), 1) if latencies else None,
        "configured_timeout_ms": timeout_ms,
        "malformed_response_count": malformed,
        "malformed_response_rate": round(malformed / len(CONTROLLED_FINDINGS), 4),
        "retry_count": retries,
        "provider_attempt_count": len(nvidia_attempts),
        "all_responses_within_timeout": all_within_timeout,
        "passed": passed,
    }


def main() -> int:
    metrics = asyncio.run(run())
    print(json.dumps(metrics, indent=2, sort_keys=True))
    return 0 if metrics["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
