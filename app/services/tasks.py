from __future__ import annotations

"""Compatibility task entry points for the asynchronous scan workers."""

import asyncio
import uuid

from app.services.orchestration.scan_orchestrator import scan_orchestrator


async def run_file_scan(scan_id: uuid.UUID, file_path: str):
    await scan_orchestrator.execute(scan_id, source_path=file_path)


async def run_url_scan(scan_id: uuid.UUID, target_url: str):
    await scan_orchestrator.execute(scan_id, options={"target_url": target_url})


async def run_github_repo_scan(scan_id: uuid.UUID, user_id: uuid.UUID, owner: str, repository: str, branch: str, folder: str = ""):
    await scan_orchestrator.execute(scan_id, user_id=user_id, options={"owner": owner, "repository": repository, "branch": branch, "folder": folder})


def run_file_scan_sync(scan_id: uuid.UUID, file_path: str) -> None:
    asyncio.run(run_file_scan(scan_id, file_path))


def run_url_scan_sync(scan_id: uuid.UUID, target_url: str) -> None:
    asyncio.run(run_url_scan(scan_id, target_url))


def run_github_repo_scan_sync(scan_id: uuid.UUID, user_id: uuid.UUID, owner: str, repository: str, branch: str, folder: str = "") -> None:
    asyncio.run(run_github_repo_scan(scan_id, user_id, owner, repository, branch, folder))
