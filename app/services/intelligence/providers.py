from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx

from app.config import settings


@dataclass(slots=True)
class IntelligenceHit:
    source: str
    identifier: str
    summary: str | None = None
    cvss_score: float | None = None
    severity: str | None = None
    published_date: str | None = None
    references: list[str] | None = None
    raw: dict[str, Any] | None = None


class ThreatProvider(ABC):
    name: str

    @abstractmethod
    async def search(self, client: httpx.AsyncClient, query: str, *, limit: int = 5) -> list[IntelligenceHit]:
        raise NotImplementedError


class NVDProvider(ThreatProvider):
    name = "NVD"

    async def search(self, client: httpx.AsyncClient, query: str, *, limit: int = 5) -> list[IntelligenceHit]:
        headers = {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}
        response = await client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": query, "resultsPerPage": min(max(limit, 1), 20)},
            headers=headers,
        )
        if response.status_code != 200:
            return []
        data = response.json()
        hits: list[IntelligenceHit] = []
        for item in data.get("vulnerabilities", [])[:limit]:
            cve_data = item.get("cve", {})
            descriptions = cve_data.get("descriptions", [])
            summary = next((entry.get("value") for entry in descriptions if entry.get("lang") == "en"), None)
            cvss_score = _extract_cvss(cve_data.get("metrics", {}))
            hits.append(
                IntelligenceHit(
                    source=self.name,
                    identifier=cve_data.get("id") or query,
                    summary=(summary or "")[:500] or None,
                    cvss_score=cvss_score,
                    published_date=cve_data.get("published"),
                    references=[ref.get("url") for ref in cve_data.get("references", []) if ref.get("url")],
                    raw=cve_data,
                )
            )
        return hits


class CIRCLProvider(ThreatProvider):
    name = "CIRCL"

    async def search(self, client: httpx.AsyncClient, query: str, *, limit: int = 5) -> list[IntelligenceHit]:
        response = await client.get(f"{settings.CVE_CIRCL_API_URL}/search/{query}")
        if response.status_code != 200:
            return []
        data = response.json()
        if not isinstance(data, list):
            return []
        hits: list[IntelligenceHit] = []
        for item in data[:limit]:
            hits.append(
                IntelligenceHit(
                    source=self.name,
                    identifier=item.get("id") or query,
                    summary=(item.get("summary") or "")[:500] or None,
                    cvss_score=item.get("cvss"),
                    published_date=item.get("Published"),
                    references=item.get("references") or [],
                    raw=item,
                )
            )
        return hits


class OSVProvider(ThreatProvider):
    name = "OSV"

    async def search(self, client: httpx.AsyncClient, query: str, *, limit: int = 5) -> list[IntelligenceHit]:
        response = await client.post(
            f"{settings.OSV_API_URL}/query",
            json={"query": query, "limit": min(max(limit, 1), 20)},
        )
        if response.status_code != 200:
            return []
        data = response.json()
        vulns = data.get("vulns", []) if isinstance(data, dict) else []
        hits: list[IntelligenceHit] = []
        for item in vulns[:limit]:
            affected = item.get("affected", [])
            aliases = item.get("aliases", []) or []
            hits.append(
                IntelligenceHit(
                    source=self.name,
                    identifier=item.get("id") or (aliases[0] if aliases else query),
                    summary=(item.get("summary") or item.get("details") or "")[:500] or None,
                    severity=item.get("severity", [{}])[0].get("type") if item.get("severity") else None,
                    published_date=item.get("published"),
                    references=[ref.get("url") for ref in item.get("references", []) if ref.get("url")],
                    raw={"affected": affected, **item},
                )
            )
        return hits


class GitHubAdvisoryProvider(ThreatProvider):
    name = "GITHUB_ADVISORY"

    async def search(self, client: httpx.AsyncClient, query: str, *, limit: int = 5) -> list[IntelligenceHit]:
        response = await client.get(
            settings.GITHUB_ADVISORY_API_URL,
            params={"query": query, "per_page": min(max(limit, 1), 20)},
            headers={"Accept": "application/vnd.github+json"},
        )
        if response.status_code != 200:
            return []
        data = response.json()
        if isinstance(data, dict):
            data = data.get("advisories", [])
        if not isinstance(data, list):
            return []
        hits: list[IntelligenceHit] = []
        for item in data[:limit]:
            hits.append(
                IntelligenceHit(
                    source=self.name,
                    identifier=item.get("ghsa_id") or item.get("cve_id") or query,
                    summary=(item.get("summary") or item.get("description") or "")[:500] or None,
                    severity=item.get("severity"),
                    published_date=item.get("published_at"),
                    references=[item.get("html_url")] if item.get("html_url") else [],
                    raw=item,
                )
            )
        return hits


class CISAKEVProvider(ThreatProvider):
    name = "CISA_KEV"

    async def search(self, client: httpx.AsyncClient, query: str, *, limit: int = 5) -> list[IntelligenceHit]:
        response = await client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        if response.status_code != 200:
            return []
        data = response.json()
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        query_lower = query.lower()
        hits: list[IntelligenceHit] = []
        for item in vulns:
            cve = (item.get("cveID") or "").lower()
            title = (item.get("vulnerabilityName") or "").lower()
            if query_lower not in cve and query_lower not in title:
                continue
            hits.append(
                IntelligenceHit(
                    source=self.name,
                    identifier=item.get("cveID") or query,
                    summary=item.get("vulnerabilityName"),
                    published_date=item.get("dateAdded"),
                    references=[item.get("notes") or ""] if item.get("notes") else [],
                    raw=item,
                )
            )
            if len(hits) >= limit:
                break
        return hits


class EPSSProvider(ThreatProvider):
    name = "EPSS"

    async def search(self, client: httpx.AsyncClient, query: str, *, limit: int = 5) -> list[IntelligenceHit]:
        response = await client.get("https://api.first.org/data/v1/epss", params={"cve": query})
        if response.status_code != 200:
            return []
        data = response.json()
        rows = data.get("data", []) if isinstance(data, dict) else []
        hits: list[IntelligenceHit] = []
        for item in rows[:limit]:
            hits.append(
                IntelligenceHit(
                    source=self.name,
                    identifier=item.get("cve") or query,
                    summary=f"EPSS probability {item.get('epss')} with percentile {item.get('percentile')}",
                    raw=item,
                )
            )
        return hits


def build_default_providers() -> list[ThreatProvider]:
    providers: list[ThreatProvider] = []
    if settings.ENABLE_NVD_LOOKUP:
        providers.append(NVDProvider())
    if settings.ENABLE_CIRCL_LOOKUP:
        providers.append(CIRCLProvider())
    if settings.ENABLE_OSV_LOOKUP:
        providers.append(OSVProvider())
    if settings.ENABLE_GITHUB_ADVISORY_LOOKUP:
        providers.append(GitHubAdvisoryProvider())
    if settings.ENABLE_CISA_KEV_LOOKUP:
        providers.append(CISAKEVProvider())
    if settings.ENABLE_EPSS_LOOKUP:
        providers.append(EPSSProvider())
    return providers


def _extract_cvss(metrics: dict[str, Any]) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            return entries[0].get("cvssData", {}).get("baseScore")
    return None
