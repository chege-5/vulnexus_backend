"""Controlled eight-finding remediation smoke test with safe summary output."""
from __future__ import annotations

import asyncio

from app.services.ai.explanations import AIExplanationService, AIExplanationUnavailable


async def main() -> None:
    service = AIExplanationService()
    payload = service.payload_builder.build(
        scan_id="controlled-eight-finding-smoke",
        scan_type="url",
        target="https://example.com",
        findings=[
            {
                "id": f"controlled-finding-{index}",
                "rule_id": f"CONTROLLED_RULE_{index}",
                "title": "Controlled TLS configuration finding",
                "severity": "Medium",
                "evidence": {"summary": "Synthetic non-sensitive test finding."},
                "remediation": "Apply the documented secure configuration and rerun the scan.",
            }
            for index in range(8)
        ],
    )
    try:
        result = await service.remediate(payload=payload)
        print({
            "outcome": "completed" if not result.unresolved_finding_ids else "partial_or_retrying",
            "validated_count": len(result.findings),
            "unresolved_count": len(result.unresolved_finding_ids),
            "unresolved_ids": result.unresolved_finding_ids,
            "attempts": [
                {
                    key: attempt.get(key)
                    for key in ("provider", "model", "http_status", "latency_ms", "result_count", "invalid_count", "error_category", "schema_failure_category", "retryable")
                }
                for attempt in result.attempts
            ],
        })
    except AIExplanationUnavailable as exc:
        print({
            "outcome": "provider_failure",
            "category": exc.category,
            "attempts": [
                {
                    key: attempt.get(key)
                    for key in ("provider", "model", "http_status", "latency_ms", "result_count", "invalid_count", "error_category", "schema_failure_category", "retryable")
                }
                for attempt in exc.attempts
            ],
        })


if __name__ == "__main__":
    asyncio.run(main())
