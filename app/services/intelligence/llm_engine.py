from __future__ import annotations

"""Provider-pluggable LLM layer that only explains data already produced by Vulnexus."""

import json
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlparse
from typing import Any, Protocol

import httpx

from app.config import settings
from app.services.intelligence.rag_store import knowledge_store


class LLMProvider(Protocol):
    name: str

    def generate(self, *, prompt: str, context: dict[str, Any]) -> str:
        raise NotImplementedError


@dataclass(slots=True)
class RuleBasedProvider:
    name: str = "rule-based"

    def generate(self, *, prompt: str, context: dict[str, Any]) -> str:
        title = context.get("title") or "Security finding"
        risk = context.get("risk", {})
        evidence = context.get("evidence", [])
        recommendations = context.get("recommendations", [])
        evidence_summary = ", ".join(item.get("title") or item.get("rule_id") or "finding" for item in evidence[:3]) if isinstance(evidence, list) else ""
        recommendation_text = "; ".join(recommendations[:3]) if isinstance(recommendations, list) else ""
        return (
            f"{title}: risk {risk.get('severity', 'Medium')} with score {risk.get('score', 0)}. "
            f"Evidence drivers: {evidence_summary}. "
            f"Recommended actions: {recommendation_text}."
        )


class LLMRateLimitExceeded(RuntimeError):
    pass


class InMemoryRateLimiter:
    def __init__(self, limit: str) -> None:
        self.max_requests, self.window_seconds = self._parse_limit(limit)
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def acquire(self) -> None:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            self._timestamps = [stamp for stamp in self._timestamps if stamp > cutoff]
            if len(self._timestamps) >= self.max_requests:
                raise LLMRateLimitExceeded("LLM API request rate limit exceeded")
            self._timestamps.append(now)

    def _parse_limit(self, value: str) -> tuple[int, float]:
        raw = (value or "").strip().lower()
        if not raw:
            return 30, 60.0
        if "/" not in raw:
            try:
                return max(int(raw), 1), 60.0
            except ValueError:
                return 30, 60.0
        amount, period = raw.split("/", 1)
        try:
            max_requests = max(int(amount.strip()), 1)
        except ValueError:
            max_requests = 30
        period = period.strip()
        if period in {"second", "seconds", "sec", "s"}:
            return max_requests, 1.0
        if period in {"hour", "hours", "h"}:
            return max_requests, 3600.0
        return max_requests, 60.0


class OpenAICompatibleProvider:
    def __init__(
        self,
        *,
        name: str = "llm-provider",
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        rate_limiter: InMemoryRateLimiter | None = None,
    ) -> None:
        self.name = name
        self.api_key = api_key or settings.OPENAI_API_KEY
        self.base_url = base_url or settings.OPENAI_BASE_URL
        self.model = model or settings.OPENAI_MODEL
        self.rate_limiter = rate_limiter or InMemoryRateLimiter(settings.LLM_RATE_LIMIT)
        self.fallback = RuleBasedProvider()

    def generate(self, *, prompt: str, context: dict[str, Any]) -> str:
        if not self.api_key:
            return self.fallback.generate(prompt=prompt, context=context)

        try:
            self.rate_limiter.acquire()
            response = self._request(prompt=prompt, context=context)
            generated = self._extract_text(response)
            return generated or self.fallback.generate(prompt=prompt, context=context)
        except (httpx.HTTPError, LLMRateLimitExceeded, ValueError, KeyError, TypeError):
            return self.fallback.generate(prompt=prompt, context=context)

    def _request(self, *, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        url = self._chat_completions_url(self.base_url)
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are VulNexus' security explanation engine. Use only the supplied JSON context. "
                        "Do not invent CVEs, exploit status, vendors, dates, or evidence."
                    ),
                },
                {
                    "role": "user",
                    "content": f"{prompt}\n\nContext JSON:\n{self._safe_json(context)}",
                },
            ],
            "temperature": settings.OPENAI_TEMPERATURE,
            "max_tokens": settings.OPENAI_MAX_TOKENS,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        with httpx.Client(timeout=settings.OPENAI_TIMEOUT_SECONDS) as client:
            response = client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()

    def _chat_completions_url(self, base_url: str) -> str:
        clean = (base_url or "").strip().rstrip("/")
        if not clean:
            clean = "https://api.openai.com/v1"
        path = urlparse(clean).path.rstrip("/")
        if path.endswith("/chat/completions"):
            return clean
        return f"{clean}/chat/completions"

    def _safe_json(self, context: dict[str, Any]) -> str:
        return json.dumps(context, sort_keys=True, default=str)[:12000]

    def _extract_text(self, payload: dict[str, Any]) -> str:
        choices = payload.get("choices") or []
        if not choices:
            return ""
        message = choices[0].get("message") or {}
        content = message.get("content") or choices[0].get("text") or ""
        if isinstance(content, list):
            return " ".join(str(part.get("text") or part.get("content") or "") if isinstance(part, dict) else str(part) for part in content).strip()
        return str(content).strip()


class LLMIntelligenceEngine:
    def __init__(self, provider: LLMProvider | None = None) -> None:
        self.provider: LLMProvider = provider or self._default_provider()

    def _default_provider(self) -> LLMProvider:
        if settings.LLM_ENABLED:
            return OpenAICompatibleProvider(name=getattr(settings, "OPENAI_MODEL", "llm-provider"))
        return RuleBasedProvider()

    def explain(self, *, title: str, audience: str, knowledge: dict[str, Any], risk: dict[str, Any], evidence: list[dict[str, Any]], recommendations: list[str]) -> dict[str, Any]:
        query = " ".join(filter(None, [title, audience, knowledge.get("threat_category"), knowledge.get("attack_surface_category")]))
        retrieved = knowledge_store.retrieve(query, topics=[audience, knowledge.get("threat_category", "")], limit=4)
        prompt = self._build_prompt(title=title, audience=audience)
        explanation = self.provider.generate(prompt=prompt, context={"title": title, "audience": audience, "risk": risk, "evidence": evidence, "recommendations": recommendations})
        return {
            "title": title,
            "audience": audience,
            "summary": explanation,
            "executive_explanation": self._format_audience_text("executive", title, knowledge, risk, retrieved),
            "technical_explanation": self._format_audience_text("technical", title, knowledge, risk, retrieved),
            "developer_explanation": self._format_audience_text("developer", title, knowledge, risk, retrieved),
            "manager_explanation": self._format_audience_text("manager", title, knowledge, risk, retrieved),
            "junior_analyst_explanation": self._format_audience_text("junior analyst", title, knowledge, risk, retrieved),
            "learning_summary": self._build_learning_summary(retrieved),
            "retrieved_context": retrieved,
        }

    def answer_report_question(self, *, question: str, report_context: dict[str, Any]) -> dict[str, str]:
        """Answer a follow-up strictly from the completed scan-report context."""
        title = f"Security report for {report_context.get('target') or 'scanned asset'}"
        prompt = (
            f"Answer this follow-up question about the completed VulNexus security report: {question}\n\n"
            "Use only the supplied report context. If the context does not establish an answer, say so. "
            "Do not invent CVEs, exploit status, affected assets, or remediation results."
        )
        answer = self.provider.generate(prompt=prompt, context=report_context)
        return {
            "answer": answer,
            "provider": self.provider.name,
            "label": "AI-assisted answer; validate against the scan evidence.",
            "title": title,
        }

    def _build_prompt(self, *, title: str, audience: str) -> str:
        return f"Explain the security finding {title} for {audience}. Use only Vulnexus evidence and retrieved references. Do not invent facts."

    def _format_audience_text(self, audience: str, title: str, knowledge: dict[str, Any], risk: dict[str, Any], retrieved: list[dict[str, Any]]) -> str:
        snippets = ", ".join(item.get("title", "reference") for item in retrieved[:2])
        return (
            f"{audience.title()} view for {title}: {knowledge.get('business_impact', 'Review impact in context of the affected asset.')}. "
            f"Risk score {risk.get('score', 0)} with severity {risk.get('severity', 'Medium')}. "
            f"Grounding references: {snippets}."
        )

    def _build_learning_summary(self, retrieved: list[dict[str, Any]]) -> str:
        if not retrieved:
            return "No additional references were retrieved."
        return " ".join(f"{item['source']}: {item['title']}" for item in retrieved[:3])


llm_engine = LLMIntelligenceEngine()
