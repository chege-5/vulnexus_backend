from __future__ import annotations

"""Provider-pluggable LLM layer that only explains data already produced by Vulnexus."""

from dataclasses import dataclass
from typing import Any, Protocol

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


class OpenAICompatibleProvider:
    def __init__(self, *, name: str = "llm-provider") -> None:
        self.name = name

    def generate(self, *, prompt: str, context: dict[str, Any]) -> str:
        return RuleBasedProvider().generate(prompt=prompt, context=context)


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
