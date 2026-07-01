import os
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app.auth import get_current_user
from app.rate_limit import limiter
from app.models.db_models import Scan, ScanStatus, User, Vulnerability, CVEEntry, ComplianceCheck
from app.models.pydantic_models import ReportListItem
from app.config import settings
from app.services.report_generator import build_report, generate_html_report, build_report_payload
from app.services.rbac import Permission, require_permission
from app.services.audit_engine import build_ai_insight, derive_final_audit_verdict
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.get("/reports", response_model=list[ReportListItem])
@limiter.limit("20/minute")
async def list_reports(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORT_READ)),
):
    reports_dir = os.path.join(settings.UPLOAD_DIR, "reports")
    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id, Scan.status == ScanStatus.COMPLETED.value)
        .order_by(Scan.finished_at.desc())
        .limit(50)
    )

    items = []
    for scan in result.scalars().all():
        scan_id = str(scan.id)
        pdf_path = os.path.join(reports_dir, f"{scan_id}.pdf")
        html_path = os.path.join(reports_dir, f"{scan_id}.html")
        has_report = os.path.exists(pdf_path) or os.path.exists(html_path)
        finished = scan.finished_at.strftime("%Y-%m-%d") if scan.finished_at else "—"
        scan_label = "URL Scan" if scan.type == "url" else "File Scan"
        items.append(ReportListItem(
            id=scan.id,
            name=f"Security Report — {scan.target}",
            type=scan_label,
            target=scan.target,
            date=finished,
            status="ready" if has_report else "generating",
            format="PDF" if os.path.exists(pdf_path) else "HTML",
        ))
    return items


@router.get("/report/{scan_id}")
@limiter.limit("10/minute")
async def download_report(
    scan_id: uuid.UUID,
    request: Request,
    format: str = "pdf",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORT_READ)),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    if scan.status != ScanStatus.COMPLETED.value:
        raise HTTPException(status_code=400, detail="Scan not yet completed")

    vulns_result = await db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan_id))
    vulnerabilities = vulns_result.scalars().all()
    compliance_result = await db.execute(select(ComplianceCheck).where(ComplianceCheck.scan_id == scan_id))
    compliance_checks = compliance_result.scalars().all()
    vuln_dicts = []
    cve_ids = set()
    known_exploit_count = 0
    for vuln in vulnerabilities:
        vuln_dicts.append({
            "rule_id": vuln.rule_id,
            "description": vuln.description,
            "severity": vuln.severity,
            "ml_score": vuln.ml_score,
            "cve_id": vuln.cve_id,
            "cvss_score": vuln.cvss_score,
            "file_path": vuln.file_path,
            "line_number": vuln.line_number,
            "remediation": vuln.remediation,
            "cwe_ids": vuln.cwe_ids,
            "owasp_category": vuln.owasp_category,
            "nist_control": vuln.nist_control,
            "mitre_technique": vuln.mitre_technique,
            "known_exploit": vuln.known_exploit,
        })
        if vuln.cve_id:
            cve_ids.add(vuln.cve_id)
        if vuln.known_exploit:
            known_exploit_count += 1

    cve_details = []
    if cve_ids:
        cve_result = await db.execute(select(CVEEntry).where(CVEEntry.cve_id.in_(cve_ids)))
        for entry in cve_result.scalars().all():
            cve_details.append({
                "cve_id": entry.cve_id,
                "summary": entry.summary,
                "cvss_score": entry.cvss_score,
                "published_date": entry.published_date.isoformat() if entry.published_date else None,
            })

    compliance_payload = [
        {
            "standard": item.standard,
            "category": item.category,
            "result": item.result,
            "score": item.score,
            "details": item.details or {},
        }
        for item in compliance_checks
    ]

    compliance_score = None
    if compliance_payload:
        passed = sum(1 for item in compliance_payload if item["result"] == "pass")
        compliance_score = round((passed / len(compliance_payload)) * 100, 2)

    final_audit = derive_final_audit_verdict(
        overall_score=scan.overall_score or 0,
        compliance_score=compliance_score,
        critical_findings=sum(1 for vuln in vulnerabilities if vuln.severity == "Critical"),
        high_findings=sum(1 for vuln in vulnerabilities if vuln.severity == "High"),
        cve_count=len(cve_ids),
        known_exploit_count=known_exploit_count,
    )

    ai_insight = build_ai_insight(
        target=scan.target,
        scan_type=scan.type,
        overall_score=scan.overall_score or 0,
        compliance_score=compliance_score,
        verdict=final_audit,
        vulnerabilities=vuln_dicts,
    )

    payload = build_report_payload(
        scan_id=scan.id,
        target=scan.target,
        scan_type=scan.type,
        overall_score=scan.overall_score or 0,
        vulnerabilities=vuln_dicts,
        cve_details=cve_details,
        compliance_checks=compliance_payload,
        audit_verdict=final_audit,
        ai_insight=ai_insight,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
    )

    report_format = (format or "pdf").lower()
    if report_format == "json":
        return JSONResponse(payload)

    reports_dir = os.path.join(settings.UPLOAD_DIR, "reports")
    pdf_path = os.path.join(reports_dir, f"{scan_id}.pdf")
    html_path = os.path.join(reports_dir, f"{scan_id}.html")

    if report_format == "html":
        if os.path.exists(html_path):
            return FileResponse(
                html_path,
                media_type="text/html",
                filename=f"vulnexus_report_{scan_id}.html",
            )
        return HTMLResponse(
            generate_html_report(
                scan_id=str(scan.id),
                target=scan.target,
                scan_type=scan.type,
                overall_score=scan.overall_score or 0,
                vulnerabilities=vuln_dicts,
                cve_details=cve_details,
                compliance_checks=compliance_payload,
                audit_verdict=final_audit,
                ai_insight=ai_insight,
                started_at=str(scan.started_at) if scan.started_at else None,
                finished_at=str(scan.finished_at) if scan.finished_at else None,
            )
        )

    if os.path.exists(pdf_path):
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=f"vulnexus_report_{scan_id}.pdf",
        )
    if os.path.exists(html_path):
        return FileResponse(
            html_path,
            media_type="text/html",
            filename=f"vulnexus_report_{scan_id}.html",
        )

    pdf_generated = build_report(
        scan_id=scan.id,
        target=scan.target,
        scan_type=scan.type,
        overall_score=scan.overall_score or 0,
        vulnerabilities=vuln_dicts,
        cve_details=cve_details,
        compliance_checks=compliance_payload,
        audit_verdict=final_audit,
        ai_insight=ai_insight,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
    )
    if pdf_generated.endswith(".html"):
        return FileResponse(pdf_generated, media_type="text/html", filename=f"vulnexus_report_{scan_id}.html")
    return FileResponse(pdf_generated, media_type="application/pdf", filename=f"vulnexus_report_{scan_id}.pdf")
    raise HTTPException(status_code=404, detail="Report not found")
