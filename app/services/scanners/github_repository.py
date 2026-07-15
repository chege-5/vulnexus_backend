from __future__ import annotations

from pathlib import Path

from app.config import settings
from app.utils.logger import get_logger
from app.services.github_repo_scanner import materialize_repository_source
from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner
from app.utils.crypto import decrypt_token
from app import database
from app.models.db_models import GitHubConnection
from sqlalchemy import select


logger = get_logger(__name__)


class GitHubRepositoryScanner(TargetScanner):
    name = "github_repository"
    supported_kinds = {"github", "repository"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        owner = context.options.get("owner") or target.metadata.get("owner")
        repository = context.options.get("repository") or target.metadata.get("repository")
        branch = context.options.get("branch") or target.metadata.get("branch") or "main"
        folder = context.options.get("folder") or target.metadata.get("folder") or ""
        user_id = context.user_id
        if not owner or not repository or not user_id:
            return ScannerResult(findings=[self._finding(
                finding_type="repository",
                title="GitHub scan configuration incomplete",
                description="GitHub repository scan missing owner, repository, or user context",
                severity="High",
                evidence={"owner": owner, "repository": repository, "user_id": str(user_id) if user_id else None},
                location=target.value,
                confidence=1.0,
                target=target.value,
                tags=["github"],
            )])

        async with database.async_session_maker() as db:
            result = await db.execute(select(GitHubConnection).where(GitHubConnection.user_id == user_id))
            connection = result.scalar_one_or_none()
            if not connection or not connection.is_connected:
                return ScannerResult(findings=[self._finding(
                    finding_type="repository",
                    title="GitHub account not connected",
                    description="GitHub account is not connected for repository scan",
                    severity="High",
                    evidence={"owner": owner, "repository": repository},
                    location=target.value,
                    confidence=1.0,
                    target=target.value,
                    tags=["github"],
                )])
            access_token = await decrypt_token(connection.access_token)

        scan_root = Path(context.options.get("scan_root") or Path(settings.UPLOAD_DIR) / str(context.scan_id) / "repository")
        scan_root.mkdir(parents=True, exist_ok=True)
        try:
            source_files = await materialize_repository_source(access_token, owner, repository, branch, str(scan_root), folder)
        except Exception as exc:
            logger.warning("GitHub repository materialization failed for %s/%s@%s: %s", owner, repository, branch, exc)
            return ScannerResult(metadata={"error": str(exc), "source_files": [], "scan_root": str(scan_root)})
        findings = [self._finding(
            finding_type="repository",
            title="Repository materialized",
            description=f"Downloaded {len(source_files)} source files from GitHub",
            severity="Info",
            evidence={"files": source_files[:10]},
            location=f"{owner}/{repository}@{branch}",
            confidence=1.0,
            raw_data={"source_files": source_files},
            target=target.value,
            tags=["github", "materialization"],
        )]
        return ScannerResult(findings=findings, metadata={"source_files": source_files, "scan_root": str(scan_root)})
