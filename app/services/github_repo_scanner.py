"""GitHub repository source materialization for direct repository scans."""
from __future__ import annotations

import base64
from pathlib import Path
from typing import Optional

from app.core.http_client import create_async_client, request_with_retry
from app.utils.file_utils import ALLOWED_EXTENSIONS
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def materialize_repository_source(
    access_token: str,
    owner: str,
    repository: str,
    branch: str,
    destination_dir: str,
    folder: str = "",
) -> list[str]:
    """Download supported source files from a GitHub repository into a local scan directory."""
    prefix = _normalize_folder(folder)
    saved_files: list[str] = []
    headers = _github_headers(access_token)

    async with create_async_client(timeout=30) as client:
        tree_response = await request_with_retry(
            client,
            "GET",
            f"https://api.github.com/repos/{owner}/{repository}/git/trees/{branch}",
            params={"recursive": 1},
            headers=headers,
        )
        if tree_response is None or tree_response.status_code != 200:
            raise ValueError("Unable to list repository tree from GitHub")

        tree_data = tree_response.json()
        entries = tree_data.get("tree", [])
        if not entries:
            raise ValueError("No repository contents were returned by GitHub")

        for entry in entries:
            if entry.get("type") != "blob":
                continue

            relative_path = entry.get("path", "")
            if prefix and not relative_path.startswith(prefix):
                continue

            if Path(relative_path).suffix.lower() not in ALLOWED_EXTENSIONS:
                continue

            content = await _download_file_content(
                client=client,
                owner=owner,
                repository=repository,
                path=relative_path,
                branch=branch,
                headers=headers,
            )
            if content is None:
                continue

            local_path = Path(destination_dir) / relative_path
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_text(content, encoding="utf-8", errors="ignore")
            saved_files.append(str(local_path))

    if not saved_files:
        raise ValueError("No supported source files were found in the selected repository path")

    logger.info("Materialized %s files from %s/%s@%s", len(saved_files), owner, repository, branch)
    return saved_files


async def fetch_repository_metadata(access_token: str, owner: str, repository: str, branch: str) -> dict:
    """Fetch repository metadata for scan context and UI display."""
    headers = _github_headers(access_token)
    async with create_async_client(timeout=20) as client:
        repo_response = await request_with_retry(
            client,
            "GET",
            f"https://api.github.com/repos/{owner}/{repository}",
            headers=headers,
        )
        branches_response = await request_with_retry(
            client,
            "GET",
            f"https://api.github.com/repos/{owner}/{repository}/branches",
            params={"per_page": 100},
            headers=headers,
        )

    repo_payload = repo_response.json() if repo_response.status_code == 200 else {}
    branches: list[str] = []
    if branches_response.status_code == 200:
        branches = [item.get("name") for item in branches_response.json() if item.get("name")]

    return {
        "organization": owner,
        "repository": repository,
        "branch": branch,
        "default_branch": repo_payload.get("default_branch"),
        "private": repo_payload.get("private", False),
        "html_url": repo_payload.get("html_url"),
        "description": repo_payload.get("description"),
        "permissions": repo_payload.get("permissions") or {},
        "branches": branches,
    }


async def _download_file_content(
    client: httpx.AsyncClient,
    owner: str,
    repository: str,
    path: str,
    branch: str,
    headers: dict[str, str],
) -> Optional[str]:
    response = await request_with_retry(
        client,
        "GET",
        f"https://api.github.com/repos/{owner}/{repository}/contents/{path}",
        params={"ref": branch},
        headers=headers,
    )
    if response is None or response.status_code != 200:
        return None

    payload = response.json()
    if payload.get("encoding") == "base64" and payload.get("content"):
        raw = payload["content"].replace("\n", "")
        return base64.b64decode(raw).decode("utf-8", errors="ignore")

    return None


def _normalize_folder(folder: str) -> str:
    clean = (folder or "").strip().lstrip("/").rstrip("/")
    return f"{clean}/" if clean else ""


def _github_headers(access_token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
