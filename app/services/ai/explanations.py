from __future__ import annotations

import asyncio
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
        # Empty scans are a terminal, successful state.  Never turn a lack of
        # evidence into a synthetic finding or an unnecessary provider call.
        if not findings:
            return {
                "status": "not_required",
                "provider": None,
                "assisted": False,
                "summary": "No findings were available for AI review.",
                "findings_reviewed": 0,
                "provider_attempts": [],
            }

        context = redact_data({"target": target, "risk_score": score, "findings": findings[: settings.AI_REVIEW_MAX_FINDINGS]})
        prompt = (
            "Provide an assisted security explanation using only this redacted scan data. "
            "Do not claim unverified facts, invent CVEs, or alter scanner findings. "
            "Return concise prioritized remediation."
        )
        providers = (
            ("nvidia", "https://integrate.api.nvidia.com/v1", settings.NVIDIA_API_KEY, settings.NVIDIA_MODEL, settings.NVIDIA_TIMEOUT_SECONDS),
            ("openrouter", "https://openrouter.ai/api/v1", settings.OPENROUTER_API_KEY, settings.OPENROUTER_MODEL, settings.OPENROUTER_TIMEOUT_SECONDS),
        )
        attempts: list[dict[str, str]] = []
        if settings.ENABLE_AI_ENRICHMENT:
            try:
                async with asyncio.timeout(settings.AI_REVIEW_TOTAL_TIMEOUT_SECONDS):
                    for provider, base_url, api_key, model, timeout in providers:
                        if not api_key or not model.strip():
                            attempts.append({"provider": provider, "status": "disabled", "error_code": "MISSING_CONFIGURATION"})
                            continue
                        try:
                            summary = await self._request(base_url, api_key, model, timeout, prompt, context)
                            logger.info("AI explanation completed provider=%s findings=%s", provider, len(context["findings"]))
                            return self._structured_response(provider=provider, assisted=True, summary=summary, context=context, attempts=attempts)
                        except Exception as exc:
                            attempts.append({"provider": provider, "status": "failed", "error_code": self._error_code(exc)})
                            logger.warning("AI explanation provider failed provider=%s error_type=%s", provider, type(exc).__name__)
            except TimeoutError:
                return self._structured_response(
                    provider="deterministic",
                    assisted=False,
                    summary=self._deterministic_summary(context),
                    context=context,
                    attempts=attempts,
                    status="timed_out",
                )
        return self._structured_response(
            provider="deterministic",
            assisted=False,
            summary=self._deterministic_summary(context),
            context=context,
            attempts=attempts,
        )

    def _structured_response(self, *, provider: str, assisted: bool, summary: str, context: dict[str, Any], attempts: list[dict[str, str]], status: str | None = None) -> dict[str, Any]:
        finding = (context.get("findings") or [{}])[0] if isinstance(context.get("findings"), list) else {}
        severity = finding.get("severity") or "Medium"
        remediation = finding.get("remediation") or "Review the affected code or configuration, remove the unsafe pattern, and rerun the scan."
        return {
            "status": status or ("completed_ai" if assisted else "completed_fallback"),
            "provider": provider,
            "assisted": assisted,
            "findings_reviewed": len(context.get("findings") or []),
            "provider_attempts": attempts,
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

    @staticmethod
    def _error_code(exc: Exception) -> str:
        if isinstance(exc, httpx.HTTPStatusError):
            return f"HTTP_{exc.response.status_code}"
        if isinstance(exc, (httpx.TimeoutException, TimeoutError)):
            return "TIMEOUT"
        if isinstance(exc, ValueError):
            return "INVALID_RESPONSE"
        return type(exc).__name__.upper()

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
                {"role": "user", "content": f"{prompt}\n\nRedacted context: {str(context)[:settings.AI_MAX_PROMPT_CHARS]}"},
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
