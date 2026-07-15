from __future__ import annotations

import base64
import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.services.integrations.base import normalize_results
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider
from app.services.integrations.providers.target_validation import domain_from_value, public_ip_or_none


SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


class VirusTotalProvider(SimpleJsonProvider):
    provider_name = "VIRUSTOTAL"

    def _auth_headers(self) -> dict[str, str]:
        return {"x-apikey": self.settings.api_key} if self.settings.api_key else {}

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        if not self.settings.api_key:
            return normalize_results(self.provider_name, query, [], error="missing api key")

        target = self._target(query, context or {})
        if target is None:
            return normalize_results(
                self.provider_name,
                query,
                [],
                raw={"skipped": True, "reason": "unsupported_target"},
                error="VirusTotal requires a URL, domain, public IP, or SHA-256 file hash",
            )

        kind, identifier, path = target
        url = f"{self.settings.endpoint.rstrip('/')}/{path}"
        try:
            response = await client.get(url, headers=self._auth_headers())
        except httpx.TimeoutException:
            return self._skip(query, "timeout", "VirusTotal lookup timed out")

        if response.status_code == 404:
            return normalize_results(
                self.provider_name,
                query,
                [self._no_record_item(query, kind, identifier)],
                raw={"status": 404, "classification": "No Known Detection", "kind": kind, "identifier": identifier},
                status_code=response.status_code,
            )
        if response.status_code in {401, 403, 429}:
            return self._skip(query, self._reason_for_status(response.status_code), response.text, status_code=response.status_code)
        if response.status_code >= 400:
            return self._skip(query, "provider_error", response.text, status_code=response.status_code)

        payload = response.json()
        return normalize_results(
            self.provider_name,
            query,
            [self._normalize_vt_object(payload, query, kind, identifier)],
            raw=payload,
            status_code=response.status_code,
        )

    def _target(self, query: str, context: dict[str, Any]) -> tuple[str, str, str] | None:
        raw = (query or "").strip()
        target_kind = str(context.get("target_kind") or context.get("kind") or "").lower()
        file_hash = str(context.get("sha256") or "").strip()
        if file_hash and SHA256_RE.match(file_hash):
            return ("file_hash", file_hash.lower(), f"files/{file_hash.lower()}")

        if target_kind in {"file", "file_hash", "sha256"}:
            if SHA256_RE.match(raw):
                return ("file_hash", raw.lower(), f"files/{raw.lower()}")
            return None

        ip = public_ip_or_none(raw)
        if target_kind in {"ip", "public_ip"} or ip:
            if not ip:
                return None
            return ("ip", ip, f"ip_addresses/{ip}")

        if target_kind == "domain":
            domain = domain_from_value(raw)
            return ("domain", domain, f"domains/{domain}") if domain else None

        parsed = urlsplit(raw)
        if target_kind == "url" or parsed.scheme in {"http", "https"}:
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return None
            url_id = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")
            return ("url", raw, f"urls/{url_id}")

        domain = domain_from_value(raw)
        if domain and not self._looks_like_ip(domain):
            return ("domain", domain, f"domains/{domain}")
        return None

    def _normalize_vt_object(self, payload: dict[str, Any], query: str, kind: str, identifier: str) -> dict[str, Any]:
        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        attributes = data.get("attributes", {}) if isinstance(data, dict) else {}
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        label = self._classification(stats)
        summary = f"{label}: {malicious} malicious, {suspicious} suspicious detections"
        return {
            "identifier": identifier,
            "summary": summary,
            "vendor": "VirusTotal",
            "classification": label,
            "signal_type": "External Intelligence",
            "reputation": attributes.get("reputation"),
            "last_analysis_stats": stats,
            "categories": attributes.get("categories") or {},
            "kind": kind,
            "raw": payload,
        }

    def _no_record_item(self, query: str, kind: str, identifier: str) -> dict[str, Any]:
        return {
            "identifier": identifier or query,
            "summary": "No Known Detection: VirusTotal has no record for this indicator",
            "vendor": "VirusTotal",
            "classification": "No Known Detection",
            "signal_type": "External Intelligence",
            "kind": kind,
            "raw": {"status": 404},
        }

    def _skip(self, query: str, reason: str, message: str, *, status_code: int | None = None):
        return normalize_results(
            self.provider_name,
            query,
            [],
            raw={"skipped": True, "reason": reason, "message": message},
            status_code=status_code,
            error=message,
        )

    def _classification(self, stats: dict[str, Any]) -> str:
        if int(stats.get("malicious") or 0) > 0:
            return "Malicious Classification"
        if int(stats.get("suspicious") or 0) > 0:
            return "Suspicious Classification"
        return "No Known Detection"

    def _reason_for_status(self, status_code: int) -> str:
        return {
            401: "invalid_api_key",
            403: "restricted_plan_or_action",
            429: "rate_limited",
        }.get(status_code, "provider_error")

    def _looks_like_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False


register_simple_provider("virustotal", lambda settings_: VirusTotalProvider(settings_))
