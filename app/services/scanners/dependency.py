from __future__ import annotations

import json
import re
from pathlib import Path

from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner


class DependencyScanner(TargetScanner):
    name = "dependency"
    supported_kinds = {"file", "github", "repository"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        paths = self._candidate_files(context, target)
        findings = []
        for path in paths:
            findings.extend(self._scan_dependency_file(path, target.value))
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

    def _scan_dependency_file(self, path: Path, target_value: str) -> list:
        findings = []
        try:
            content = path.read_text(errors="ignore")
        except Exception:
            return findings

        if path.name == "requirements.txt":
            for line in content.splitlines():
                match = re.match(r"^([A-Za-z0-9_.-]+)==([0-9][^\s#]+)", line.strip())
                if match:
                    findings.append(self._finding(
                        finding_type="dependency",
                        title=f"Pinned dependency {match.group(1)}",
                        description=f"Detected pinned dependency {match.group(1)}=={match.group(2)}",
                        severity="Medium",
                        evidence={"package": match.group(1), "version": match.group(2)},
                        location=str(path),
                        confidence=0.82,
                        raw_data={"line": line},
                        target=target_value,
                        tags=["dependency"],
                    ))
        elif path.name == "package.json":
            try:
                payload = json.loads(content)
            except Exception:
                payload = {}
            for section in ("dependencies", "devDependencies"):
                for package, version in (payload.get(section) or {}).items():
                    if isinstance(version, str) and version:
                        findings.append(self._finding(
                            finding_type="dependency",
                            title=f"JavaScript dependency {package}",
                            description=f"Detected {package} declared as {version}",
                            severity="Medium",
                            evidence={"package": package, "version": version, "section": section},
                            location=str(path),
                            confidence=0.82,
                            raw_data={"package_json": payload},
                            target=target_value,
                            tags=["dependency", "javascript"],
                        ))
        return findings