from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.services.models.pipeline import RawFinding, ScanContext, ScanTarget


@dataclass(slots=True)
class ScannerResult:
    findings: list[RawFinding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class TargetScanner(ABC):
    name: str
    supported_kinds: set[str] = {"url", "file", "github", "repository"}

    def supports(self, target: ScanTarget) -> bool:
        return target.kind in self.supported_kinds

    @abstractmethod
    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        raise NotImplementedError

    def _finding(
        self,
        *,
        finding_type: str,
        title: str,
        description: str,
        severity: str = "Medium",
        evidence: dict[str, Any] | None = None,
        location: str | None = None,
        confidence: float = 0.5,
        source: str | None = None,
        tags: list[str] | None = None,
        raw_data: dict[str, Any] | None = None,
        target: str | None = None,
    ) -> RawFinding:
        return RawFinding(
            type=finding_type,
            title=title,
            description=description,
            severity=severity,
            evidence=evidence or {},
            location=location,
            confidence=confidence,
            source=source or self.name,
            tags=tags or [],
            raw_data=raw_data or {},
            target=target,
        )