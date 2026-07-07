from __future__ import annotations

import json
import re
from pathlib import Path

from app.config import settings
from app.core.http_client import create_async_client, request_with_retry
from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner


class DependencyScanner(TargetScanner):
    name = "dependency"
    supported_kinds = {"file", "github", "repository"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        paths = self._candidate_files(context, target)
        findings = []
        for path in paths:
            dependencies = self._scan_dependency_file(path)
            findings.extend([self._dependency_observation(path, dep, target.value) for dep in dependencies])
            findings.extend(await self._osv_findings(path, dependencies, target.value))
        return ScannerResult(findings=findings, metadata={"dependency_files": len(paths)})

    def _candidate_files(self, context: ScanContext, target: ScanTarget) -> list[Path]:
        source_files = [Path(path) for path in (context.options.get("source_files") or [])]
        if source_files:
            return source_files
        base = Path(context.source_path) if context.source_path else Path(target.value)
        if base.is_file():
            return [base]
        candidates = []
        for pattern in ("requirements.txt", "package.json", "pyproject.toml", "Pipfile", "pom.xml", "build.gradle", "Cargo.toml"):
            candidate = base / pattern
            if candidate.exists():
                candidates.append(candidate)
        return candidates

    def _scan_dependency_file(self, path: Path) -> list[dict]:
        dependencies = []
        try:
            content = path.read_text(errors="ignore")
        except Exception:
            return dependencies

        if path.name == "requirements.txt":
            for line in content.splitlines():
                match = re.match(r"^([A-Za-z0-9_.-]+)==([0-9][^\s#]+)", line.strip())
                if match:
                    dependencies.append({"package": match.group(1), "version": match.group(2), "ecosystem": "PyPI", "line": line})
        elif path.name == "package.json":
            try:
                payload = json.loads(content)
            except Exception:
                payload = {}
            for section in ("dependencies", "devDependencies"):
                for package, version in (payload.get(section) or {}).items():
                    cleaned = self._clean_version(version)
                    if isinstance(version, str) and cleaned:
                        dependencies.append({"package": package, "version": cleaned, "ecosystem": "npm", "section": section})
        return dependencies

    def _dependency_observation(self, path: Path, dep: dict, target_value: str):
        return self._finding(
            finding_type="dependency",
            title=f"Dependency declared: {dep['package']}",
            description=f"Detected {dep['package']} {dep.get('version') or ''} in {path.name}",
            severity="Info",
            evidence=dep,
            location=str(path),
            confidence=0.78,
            raw_data=dep,
            target=target_value,
            tags=["dependency", dep.get("ecosystem", "").lower()],
        )

    async def _osv_findings(self, path: Path, dependencies: list[dict], target_value: str) -> list:
        if not dependencies or not settings.ENABLE_OSV_LOOKUP:
            return []
        findings = []
        async with create_async_client(timeout=settings.INTELLIGENCE_REQUEST_TIMEOUT_SECONDS) as client:
            for dep in dependencies[:100]:
                response = await request_with_retry(
                    client,
                    "POST",
                    f"{settings.OSV_API_URL.rstrip('/')}/query",
                    json={"package": {"name": dep["package"], "ecosystem": dep["ecosystem"]}, "version": dep.get("version")},
                )
                if response is None or response.status_code != 200:
                    continue
                for vuln in (response.json().get("vulns") or []):
                    severity = self._severity_from_osv(vuln)
                    aliases = vuln.get("aliases") or []
                    findings.append(self._finding(
                        finding_type="dependency_vulnerability",
                        title=f"Vulnerable dependency: {dep['package']}",
                        description=vuln.get("summary") or vuln.get("details") or f"{dep['package']} is linked to advisory {vuln.get('id')}",
                        severity=severity,
                        evidence={"package": dep["package"], "version": dep.get("version"), "ecosystem": dep["ecosystem"], "advisory": vuln.get("id"), "aliases": aliases},
                        location=str(path),
                        confidence=0.92,
                        raw_data={"dependency": dep, "osv": vuln},
                        target=target_value,
                        tags=["dependency", "osv", *aliases[:5]],
                    ))
        return findings

    def _severity_from_osv(self, vuln: dict) -> str:
        for item in vuln.get("severity") or []:
            score = item.get("score", "")
            match = re.search(r"/AV:|^CVSS:", score)
            if match:
                if any(token in score for token in (":H", "H/")):
                    return "High"
        database_specific = vuln.get("database_specific") or {}
        if str(database_specific.get("severity", "")).upper() in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return str(database_specific["severity"]).title()
        return "High"

    def _clean_version(self, version: str) -> str:
        return re.sub(r"^[~^<>=\s]+", "", str(version)).split(" ")[0]
