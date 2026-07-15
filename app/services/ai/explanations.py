from __future__ import annotations

from typing import Any

import httpx

from app.config import settings
from app.utils.logger import get_logger
from app.utils.redaction import redact_data

logger = get_logger(__name__)


class AIExplanationUnavailable(RuntimeError):
    pass


class AIExplanationService:
    """Opt-in assisted explanations; deterministic scan data is never changed."""

    async def explain_scan(self, *, target: str, findings: list[dict[str, Any]], score: float | None) -> dict[str, Any]:
        context = redact_data({"target": target, "risk_score": score, "findings": findings[:50]})
        prompt = (
            "Provide an assisted security explanation using only this redacted scan data. "
            "Do not claim unverified facts, invent CVEs, or alter scanner findings. "
            "Return concise prioritized remediation."
        )
        providers = (
            ("nvidia", "https://integrate.api.nvidia.com/v1", settings.NVIDIA_API_KEY, settings.NVIDIA_MODEL, settings.NVIDIA_TIMEOUT_SECONDS),
            ("openrouter", "https://openrouter.ai/api/v1", settings.OPENROUTER_API_KEY, settings.OPENROUTER_MODEL, settings.OPENROUTER_TIMEOUT_SECONDS),
        )
        if settings.ENABLE_AI_ENRICHMENT:
            for provider, base_url, api_key, model, timeout in providers:
                try:
                    summary = await self._request(base_url, api_key, model, timeout, prompt, context)
                    logger.info("AI explanation completed provider=%s", provider)
                    return self._structured_response(provider=provider, assisted=True, summary=summary, context=context)
                except Exception as exc:
                    logger.warning("AI explanation provider failed provider=%s error_type=%s", provider, type(exc).__name__)
        return self._structured_response(provider="deterministic", assisted=False, summary=self._deterministic_summary(context), context=context)

    def _structured_response(self, *, provider: str, assisted: bool, summary: str, context: dict[str, Any]) -> dict[str, Any]:
        finding = (context.get("findings") or [{}])[0] if isinstance(context.get("findings"), list) else {}
        severity = finding.get("severity") or "Medium"
        remediation = finding.get("remediation") or "Review the affected code or configuration, remove the unsafe pattern, and rerun the scan."
        return {
            "provider": provider,
            "assisted": assisted,
            "label": "AI-assisted explanation; validate against scan evidence." if assisted else "Deterministic explanation generated from scan metadata.",
            "summary": summary,
            "why_it_matters": f"This finding is rated {severity} because the affected asset may expose a security weakness that should be reviewed before release.",
            "evidence_interpretation": finding.get("description") or "The scanner detected a pattern that requires human review.",
            "remediation_steps": [
                remediation,
                "Apply the change in the affected file or service configuration.",
                "Add a regression test or configuration check where practical.",
            ],
            "verification_steps": [
                "Rerun the same VulNexus scan type against the affected target.",
                "Confirm the original rule ID no longer appears in results.",
                "Review related findings for the same asset before closing the issue.",
            ],
            "priority": severity,
            "false_positive_conditions": [
                "The affected code path is unreachable in deployed builds.",
                "A compensating control exists and is documented.",
                "The evidence is from a test fixture or intentionally vulnerable sample.",
            ],
        }

    def _deterministic_summary(self, context: dict[str, Any]) -> str:
        finding = (context.get("findings") or [{}])[0] if isinstance(context.get("findings"), list) else {}
        return (
            f"{finding.get('rule_id') or 'Security finding'} on {context.get('target')}: "
            f"{finding.get('description') or 'A scanner finding requires review.'} "
            f"Recommended remediation: {finding.get('remediation') or 'fix the unsafe pattern and rerun validation.'}"
        )

    async def _request(self, base_url: str, api_key: str | None, model: str, timeout: float, prompt: str, context: dict[str, Any]) -> str:
        if not api_key:
            raise ValueError("provider is not configured")
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You explain security findings. Use only provided evidence."},
                {"role": "user", "content": f"{prompt}\n\nRedacted context: {context}"},
            ],
            "temperature": 0.2,
            "max_tokens": 700,
        }
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.post(f"{base_url.rstrip('/')}/chat/completions", json=payload, headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
        if response.status_code == 429 or response.status_code >= 500:
            raise RuntimeError(f"provider status {response.status_code}")
        response.raise_for_status()
        try:
            content = (((response.json().get("choices") or [{}])[0].get("message") or {}).get("content"))
        except (ValueError, AttributeError, IndexError, TypeError) as exc:
            raise ValueError("provider returned invalid JSON") from exc
        if not isinstance(content, str) or not content.strip():
            raise ValueError("provider returned an empty response")
        return content.strip()


ai_explanation_service = AIExplanationService()
