from celery import Celery
import asyncio
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
    import uuid
    from app.services.tasks import run_file_scan
    asyncio.run(run_file_scan(uuid.UUID(scan_id_str), file_path))

@celery_app.task(name="app.tasks.run_url_scan_task")
def run_url_scan_task(scan_id_str: str, target_url: str):
    import uuid
    from app.services.tasks import run_url_scan
    asyncio.run(run_url_scan(uuid.UUID(scan_id_str), target_url))
