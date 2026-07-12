#!/usr/bin/env python3
"""Run a direct file-scan smoke test against the configured PostgreSQL database."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from sqlalchemy import select

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app import database
from app.models.db_models import Scan, ScanStatus, ScanType, Vulnerability
from app.services.orchestration.scan_orchestrator import scan_orchestrator


async def main() -> None:
    sample = BACKEND_DIR / "tests" / "fixtures" / "security_checks" / "weak_crypto_modes_sample.py"
    async with database.async_session_maker() as db:
        scan = Scan(
            type=ScanType.FILE.value,
            target=sample.name,
            status=ScanStatus.QUEUED.value,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        scan_id = scan.id

    result = await scan_orchestrator.execute(scan_id, source_path=str(sample))

    async with database.async_session_maker() as db:
        scan = await db.get(Scan, scan_id)
        rows = (
            await db.execute(
                select(Vulnerability).where(Vulnerability.scan_id == scan_id).order_by(Vulnerability.created_at)
            )
        ).scalars().all()

    print(f"scan_id={scan_id}")
    print(f"status={scan.status if scan else result['status']}")
    print(f"finding_count={len(rows)}")
    for row in rows:
        print(
            "finding "
            f"rule_id={row.rule_id} "
            f"rule_id_len={len(row.rule_id or '')} "
            f"file_path={row.file_path} "
            f"line_number={row.line_number} "
            f"code_snippet={row.code_snippet}"
        )
    await database.close_db()


if __name__ == "__main__":
    asyncio.run(main())
