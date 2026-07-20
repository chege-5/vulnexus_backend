#!/usr/bin/env python3
"""Prove the file-SAST worker path against PostgreSQL without retaining data.

This creates one disposable scan, invokes the actual Celery task body (the
same worker entry point used after upload), verifies persisted source evidence,
then deletes the scan in ``finally``.  It is safe to rerun and prints no
source-secret values.
"""
from __future__ import annotations

import asyncio
import sys
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import select
from starlette.datastructures import UploadFile
from starlette.requests import Request

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app import database
from app.celery_app import run_file_scan_task
from app.models.db_models import Scan, ScanStatus, User, Vulnerability
from app.routes.scan_routes import scan_result, upload_file


def _request(method: str, path: str) -> Request:
    return Request({"type": "http", "method": method, "path": path, "headers": []})


async def _upload_and_queue(sample: Path):
    async with database.async_session_maker() as db:
        user = User(email=f"sast-smoke-{uuid4().hex}@example.invalid", name="SAST smoke", is_approved=True)
        db.add(user)
        await db.commit()
        await db.refresh(user)
        upload = UploadFile(filename=sample.name, file=BytesIO(sample.read_bytes()))
        with patch("app.celery_app.run_file_scan_task.delay") as queue:
            response = await upload_file(_request("POST", "/api/v1/upload-file"), upload, db, user)
            queue.assert_called_once()
            scan_id, source_path = queue.call_args.args
        await upload.close()
        return response.scan_id, user.id, source_path


async def _verify(scan_id, user_id):
    async with database.async_session_maker() as db:
        scan = await db.get(Scan, scan_id)
        rows = (await db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan_id))).scalars().all()
        user = await db.get(User, user_id)
        result = await scan_result(scan_id, _request("GET", f"/api/v1/scan-result/{scan_id}"), db, user)
    if not scan or scan.status != ScanStatus.COMPLETED.value:
        raise RuntimeError(f"file scan did not complete: {scan.status if scan else 'missing'}")
    if not rows:
        raise RuntimeError("file scan completed without persisted findings")
    required = {"source_rule_id", "line_preview", "column_number", "analysis_engine", "confidence", "category"}
    evidence = rows[0].evidence or {}
    missing = required - set(evidence)
    if missing:
        raise RuntimeError(f"persisted evidence is incomplete: {', '.join(sorted(missing))}")
    api_finding = result.vulnerabilities[0]
    if not api_finding.evidence or not api_finding.column_number or api_finding.confidence is None:
        raise RuntimeError("scan-result API dropped SAST evidence fields")
    print(f"scan_id={scan_id}")
    print(f"status={scan.status}")
    print(f"finding_count={len(rows)}")
    print(f"first_rule_id={rows[0].rule_id}")
    print(f"evidence_fields={','.join(sorted(required))}")
    print("api_contract=rule_id,evidence,source_preview,line,column,confidence,category")


async def _delete_scan(scan_id, user_id):
    async with database.async_session_maker() as db:
        scan = await db.get(Scan, scan_id)
        if scan:
            await db.delete(scan)
            await db.commit()
        user = await db.get(User, user_id)
        if user:
            await db.delete(user)
            await db.commit()


async def main() -> None:
    sample = BACKEND_DIR / "tests" / "fixtures" / "security_checks" / "sast_regression_vulnerable.py"
    scan_id, user_id, source_path = await _upload_and_queue(sample)
    # The task body deliberately owns a fresh event loop.  Dispose the setup
    # loop's asyncpg connections first so none can cross into that worker loop.
    await database.close_db()
    try:
        # Execute the synchronous Celery task body in a worker thread.  Its
        # private event loop is therefore isolated from this verifier loop.
        task_result = await asyncio.to_thread(run_file_scan_task.run, str(scan_id), source_path)
        if task_result.get("status") != ScanStatus.COMPLETED.value:
            raise RuntimeError(f"Celery task failed: {task_result.get('status')}")
        await _verify(scan_id, user_id)
        print("verified=upload_queue_worker_orchestrator_postgres_result_api")
    finally:
        await _delete_scan(scan_id, user_id)
        await database.close_db()


if __name__ == "__main__":
    asyncio.run(main())
