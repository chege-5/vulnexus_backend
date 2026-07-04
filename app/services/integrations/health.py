from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class ProviderHealth:
    provider: str
    enabled: bool
    healthy: bool
    message: str = "ok"
    endpoint: str | None = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict[str, Any] = field(default_factory=dict)