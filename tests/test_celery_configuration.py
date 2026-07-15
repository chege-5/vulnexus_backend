from app.celery_app import celery_app
from app.config import settings
from app.celery_app import run_file_scan_task
from app import database
import asyncio
from unittest.mock import AsyncMock, patch
from uuid import uuid4
from sqlalchemy.pool import NullPool


def test_celery_uses_the_configured_broker_and_result_backend():
    """Worker routing must honor explicit Celery overrides, not only REDIS_URL."""
    assert celery_app.conf.broker_url == settings.CELERY_BROKER_URL
    assert celery_app.conf.result_backend == settings.CELERY_RESULT_BACKEND
    assert celery_app.conf.worker_prefetch_multiplier == 1
    assert celery_app.conf.task_soft_time_limit == settings.CELERY_TASK_SOFT_TIME_LIMIT
    assert celery_app.conf.task_time_limit == settings.CELERY_TASK_TIME_LIMIT


def test_celery_worker_engine_uses_null_pool(monkeypatch):
    monkeypatch.setattr(settings, "VULNEXUS_CELERY_WORKER", True)
    worker_engine = database._create_engine(settings.DATABASE_URL)
    try:
        assert isinstance(worker_engine.sync_engine.pool, NullPool)
    finally:
        worker_engine.sync_engine.dispose()


def test_two_file_tasks_dispose_resources_before_each_loop_closes():
    loops = []

    async def execute(scan_id, **_kwargs):
        loops.append(asyncio.get_running_loop())
        return {"scan_id": str(scan_id), "status": "completed"}

    first_scan_id, second_scan_id = uuid4(), uuid4()
    with patch("app.services.orchestration.scan_orchestrator.scan_orchestrator.execute", side_effect=execute), patch(
        "app.celery_app.cleanup_scan_dir"
    ) as cleanup, patch("app.celery_app.database.close_db", new_callable=AsyncMock) as close_db:
        first = run_file_scan_task.run(str(first_scan_id), "first.py")
        second = run_file_scan_task.run(str(second_scan_id), "second.py")

    assert first["status"] == "completed"
    assert second["status"] == "completed"
    assert len(loops) == 2
    assert loops[0] is not loops[1]
    assert cleanup.call_count == 2
    assert close_db.await_count == 2


def test_worker_accepts_a_task_after_a_failed_scan():
    calls = 0

    async def execute(scan_id, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("controlled scan failure")
        return {"scan_id": str(scan_id), "status": "completed"}

    class NoScanSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def get(self, *_args):
            return None

    with patch("app.services.orchestration.scan_orchestrator.scan_orchestrator.execute", side_effect=execute), patch(
        "app.celery_app.cleanup_scan_dir"
    ), patch("app.celery_app.database.async_session_maker", side_effect=NoScanSession), patch(
        "app.celery_app.database.close_db", new_callable=AsyncMock
    ), patch("app.celery_app.cache.set", new_callable=AsyncMock):
        failed = run_file_scan_task.run(str(uuid4()), "broken.py")
        completed = run_file_scan_task.run(str(uuid4()), "healthy.py")

    assert failed["status"] == "failed"
    assert completed["status"] == "completed"
