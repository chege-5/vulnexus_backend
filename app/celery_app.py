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

    asyncio.run(_execute_or_fail(UUID(scan_id_str), lambda scan_id: scan_orchestrator.execute(scan_id, source_path=file_path)))

@celery_app.task(name="app.tasks.run_url_scan_task")
def run_url_scan_task(scan_id_str: str, target_url: str):
    from app.services.orchestration.scan_orchestrator import scan_orchestrator

    asyncio.run(_execute_or_fail(UUID(scan_id_str), lambda scan_id: scan_orchestrator.execute(scan_id, options={"target_url": target_url})))


@celery_app.task(name="app.tasks.run_github_scan_task")
def run_github_scan_task(scan_id_str: str, user_id_str: str, owner: str, repository: str, branch: str, folder: str = ""):
    from app.services.orchestration.scan_orchestrator import scan_orchestrator

    asyncio.run(_execute_or_fail(UUID(scan_id_str), lambda scan_id: scan_orchestrator.execute(scan_id, user_id=UUID(user_id_str), options={"owner": owner, "repository": repository, "branch": branch, "folder": folder})))


async def _execute_or_fail(scan_id: UUID, runner):
    from datetime import datetime, timezone
    from app import database
    from app.models.db_models import Scan, ScanStatus
    from app.utils.cache import cache

    try:
        return await runner(scan_id)
    except Exception as exc:
        async with database.async_session_maker() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                if scan.status == ScanStatus.CANCELED.value:
                    return None
                scan.status = ScanStatus.FAILED.value
                scan.error_message = str(exc)
                scan.finished_at = datetime.now(timezone.utc)
                await db.commit()
                await cache.set("scan_progress", str(scan_id), {
                    "scan_id": str(scan_id),
                    "status": ScanStatus.FAILED.value,
                    "progress": scan.progress or 0,
                    "stage": "failed",
                    "message": "Scan failed",
                    "error_message": str(exc),
                    "details": {},
                    "finished_at": scan.finished_at.isoformat(),
                })
        raise
