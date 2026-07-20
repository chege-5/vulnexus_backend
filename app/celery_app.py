from celery import Celery
from sqlalchemy import select
import asyncio
from datetime import datetime, timezone
from uuid import UUID

from app import database
from app.config import settings
from app.models.db_models import Scan, ScanStatus, User, Vulnerability
from app.services.email import notification_email_enabled, queue_transactional_email
from app.services.integrations.cache import cache as integration_cache
from app.utils.cache import cache, close_redis_cache
from app.utils.file_utils import cleanup_scan_dir
from app.utils.logger import get_logger
from app.utils.redaction import redact_text
from celery.signals import after_setup_logger, after_setup_task_logger

logger = get_logger(__name__)


@after_setup_logger.connect
def _configure_celery_logger(**kwargs):
    from app.utils.logger import configure_log_redaction

    configure_log_redaction(kwargs.get("logger"))


@after_setup_task_logger.connect
def _configure_celery_task_logger(**kwargs):
    from app.utils.logger import configure_log_redaction

    configure_log_redaction(kwargs.get("logger"))

celery_app = Celery(
    "vulnexus_worker",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    # The Windows worker is intentionally started with `-Q scans`. Route all
    # scan lifecycle work there so producers never leave messages stranded on
    # Celery's implicit `celery` queue.
    task_default_queue="scans",
    task_default_exchange="scans",
    task_default_routing_key="scans",
    task_routes={
        "app.tasks.run_file_scan_task": {"queue": "scans"},
        "app.tasks.run_url_scan_task": {"queue": "scans"},
        "app.tasks.run_github_scan_task": {"queue": "scans"},
        "app.tasks.run_ai_review_task": {"queue": "ai"},
    },
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=settings.CELERY_WORKER_PREFETCH_MULTIPLIER,
    task_soft_time_limit=settings.CELERY_TASK_SOFT_TIME_LIMIT,
    task_time_limit=settings.CELERY_TASK_TIME_LIMIT,
    broker_connection_retry_on_startup=True,
    result_expires=settings.CELERY_RESULT_EXPIRES_SECONDS,
)


@celery_app.task(name="app.tasks.run_file_scan_task")
def run_file_scan_task(scan_id_str: str, file_path: str):
    from app.services.orchestration.scan_orchestrator import scan_orchestrator

    logger.info("File SAST task start scan_id=%s source=%s", scan_id_str, redact_text(file_path))
    result = _run_scan_task(
        scan_id_str,
        lambda scan_id: scan_orchestrator.execute(scan_id, source_path=file_path),
    )
    logger.info("File SAST task complete scan_id=%s status=%s", scan_id_str, result.get("status"))
    return result

@celery_app.task(name="app.tasks.run_url_scan_task")
def run_url_scan_task(scan_id_str: str, target_url: str):
    from app.services.orchestration.scan_orchestrator import scan_orchestrator

    return _run_scan_task(
        scan_id_str,
        lambda scan_id: scan_orchestrator.execute(scan_id, options={"target_url": target_url}),
    )


@celery_app.task(name="app.tasks.run_github_scan_task")
def run_github_scan_task(scan_id_str: str, user_id_str: str, owner: str, repository: str, branch: str, folder: str = ""):
    from app.services.orchestration.scan_orchestrator import scan_orchestrator

    return _run_scan_task(
        scan_id_str,
        lambda scan_id: scan_orchestrator.execute(
            scan_id,
            user_id=UUID(user_id_str),
            options={"owner": owner, "repository": repository, "branch": branch, "folder": folder},
        ),
    )


@celery_app.task(name="app.tasks.run_ai_review_task")
def run_ai_review_task(scan_id_str: str):
    """Run slow assisted review after the primary scan is already complete."""
    from app.services.orchestration.scan_orchestrator import scan_orchestrator

    scan_id = UUID(scan_id_str)
    logger.info("AI review task start scan_id=%s", scan_id)
    result = _run_in_fresh_worker_loop(scan_orchestrator.run_ai_review(scan_id))
    logger.info("AI review task complete scan_id=%s status=%s", scan_id, result.get("ai_review_status"))
    return result


def _run_scan_task(scan_id_str: str, runner) -> dict:
    scan_id = UUID(scan_id_str)
    logger.info("Task start scan_id=%s", scan_id)
    try:
        result = _run_in_fresh_worker_loop(_execute_or_fail(scan_id, runner))
        logger.info("Task return scan_id=%s status=%s", scan_id, result.get("status"))
        return result
    finally:
        cleanup_scan_dir(scan_id)
        logger.info("Task cleanup complete scan_id=%s", scan_id)


def _run_in_fresh_worker_loop(coroutine):
    """Run one synchronous Celery task without leaking loop-bound clients."""
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coroutine)
    finally:
        try:
            loop.run_until_complete(_dispose_task_resources())
        except Exception:
            logger.exception("Celery task resource cleanup failed")
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                asyncio.set_event_loop(None)
                loop.close()
                logger.info("Celery task event loop closed")


async def _dispose_task_resources() -> None:
    """Dispose all loop-bound resources before the loop is closed."""
    try:
        await close_redis_cache()
        await integration_cache.close()
    except Exception:
        logger.exception("Celery Redis client cleanup failed")
    finally:
        await database.close_db()
        logger.info("Celery DB engine disposed")


async def _execute_or_fail(scan_id: UUID, runner) -> dict:
    logger.info("Scan execution start scan_id=%s", scan_id)

    try:
        result = await runner(scan_id)
        await _queue_scan_lifecycle_email(scan_id, result.get("status"))
        logger.info("Scan execution complete scan_id=%s status=%s", scan_id, result.get("status"))
        return result
    except Exception as exc:
        logger.exception("Scan execution failed scan_id=%s", scan_id)
        error_message = redact_text(str(exc))[:500] or "Scan execution failed"
        try:
            async with database.async_session_maker() as db:
                scan = await db.get(Scan, scan_id)
                if scan and scan.status == ScanStatus.CANCELED.value:
                    return {"scan_id": str(scan_id), "status": ScanStatus.CANCELED.value}
                finished_at = datetime.now(timezone.utc)
                progress = 0
                if scan:
                    progress = scan.progress or 0
                    scan.status = ScanStatus.FAILED.value
                    scan.error_message = error_message
                    scan.finished_at = finished_at
                    await db.commit()
                    logger.info("Scan failure DB commit scan_id=%s", scan_id)
                await cache.set("scan_progress", str(scan_id), {
                    "scan_id": str(scan_id),
                    "status": ScanStatus.FAILED.value,
                    "progress": progress,
                    "stage": "failed",
                    "message": "Scan failed",
                    "error_message": error_message,
                    "details": {},
                    "finished_at": finished_at.isoformat(),
                })
        except Exception:
            logger.exception("Unable to finalize failed scan_id=%s", scan_id)
        await _queue_scan_lifecycle_email(scan_id, ScanStatus.FAILED.value)
        return {"scan_id": str(scan_id), "status": ScanStatus.FAILED.value, "error_message": error_message}


async def _queue_scan_lifecycle_email(scan_id: UUID, status: str | None) -> None:
    if status not in {ScanStatus.COMPLETED.value, ScanStatus.FAILED.value}:
        return
    try:
        async with database.async_session_maker() as db:
            scan = await db.get(Scan, scan_id)
            if not scan or not scan.user_id:
                return
            user = await db.get(User, scan.user_id)
            if not user:
                return
            path = f"/dashboard/scan/results/{scan.id}" if status == ScanStatus.COMPLETED.value else f"/dashboard/scan/progress/{scan.id}"
            event = "scan_completed" if status == ScanStatus.COMPLETED.value else "scan_failed"
            if notification_email_enabled(user.email_preferences, event):
                queue_transactional_email(user.email, event, {"name": user.name, "path": path})
            if status == ScanStatus.COMPLETED.value and notification_email_enabled(user.email_preferences, "critical_finding"):
                result = await db.execute(
                    select(Vulnerability.id).where(Vulnerability.scan_id == scan.id, Vulnerability.severity.in_(["critical", "high"])).limit(1)
                )
                if result.scalar_one_or_none() is not None:
                    queue_transactional_email(user.email, "critical_finding", {"name": user.name, "path": path})
    except Exception:
        logger.exception("Scan notification email queue failed scan_id=%s", scan_id)
