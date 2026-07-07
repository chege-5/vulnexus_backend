from __future__ import annotations

from collections.abc import Callable

from app.services.integrations.base import ProviderAdapter, ProviderSettings


ProviderFactory = Callable[[ProviderSettings], ProviderAdapter]


class ProviderRegistry:
    def __init__(self) -> None:
        self._factories: dict[str, ProviderFactory] = {}

    def register(self, name: str, factory: ProviderFactory) -> None:
        self._factories[name.lower()] = factory

    def create(self, name: str, settings: ProviderSettings) -> ProviderAdapter | None:
        factory = self._factories.get(name.lower())
        return factory(settings) if factory else None

    def names(self) -> list[str]:
        return sorted(self._factories)

    def items(self) -> dict[str, ProviderFactory]:
        return dict(self._factories)


registry = ProviderRegistry()