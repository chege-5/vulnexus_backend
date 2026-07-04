from celery import Celery
import asyncio
from uuid import UUID
from app.config import settings

celery_app = Celery(
    "vulnexus_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

@celery_app.task(name="app.tasks.run_file_scan_task")
def run_file_scan_task(scan_id_str: str, file_path: str):
    from app.services.orchestration.scan_orchestrator import scan_orchestrator

    asyncio.run(scan_orchestrator.execute(UUID(scan_id_str), source_path=file_path))

@celery_app.task(name="app.tasks.run_url_scan_task")
def run_url_scan_task(scan_id_str: str, target_url: str):
    from app.services.orchestration.scan_orchestrator import scan_orchestrator

    asyncio.run(scan_orchestrator.execute(UUID(scan_id_str), options={"target_url": target_url}))


@celery_app.task(name="app.tasks.run_github_scan_task")
def run_github_scan_task(scan_id_str: str, user_id_str: str, owner: str, repository: str, branch: str, folder: str = ""):
    from app.services.orchestration.scan_orchestrator import scan_orchestrator

    asyncio.run(scan_orchestrator.execute(UUID(scan_id_str), user_id=UUID(user_id_str), options={"owner": owner, "repository": repository, "branch": branch, "folder": folder}))
