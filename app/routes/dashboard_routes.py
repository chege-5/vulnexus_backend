from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app.auth import get_current_user
from app.rate_limit import limiter
from app.models.db_models import Scan, Vulnerability, ScanStatus, Severity, User, GitHubConnection, ComplianceCheck
from app.models.pydantic_models import DashboardResponse
from app.services.rbac import Permission, require_permission
from app.services.audit_engine import build_ai_insight, derive_final_audit_verdict
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.get("/dashboard", response_model=DashboardResponse)
@limiter.limit("30/minute")
async def dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DASHBOARD_READ)),
):
    user_id = current_user.id

    total = await db.scalar(
        select(func.count()).select_from(Scan).where(Scan.user_id == user_id)
    )
    completed = await db.scalar(
        select(func.count()).select_from(Scan).where(
            Scan.user_id == user_id,
            Scan.status == ScanStatus.COMPLETED.value,
        )
    )
    failed = await db.scalar(
        select(func.count()).select_from(Scan).where(
            Scan.user_id == user_id,
            Scan.status == ScanStatus.FAILED.value,
        )
    )
    avg_score = await db.scalar(
        select(func.avg(Scan.overall_score)).where(
            Scan.user_id == user_id,
            Scan.overall_score.isnot(None),
        )
    )

    sev_counts = {}
    for sev in Severity:
        count = await db.scalar(
            select(func.count()).select_from(Vulnerability).join(Scan).where(
                Scan.user_id == user_id,
                Vulnerability.severity == sev.value,
            )
        )
        sev_counts[sev.value] = count or 0

    open_findings = await db.scalar(
        select(func.count()).select_from(Vulnerability).join(Scan).where(
            Scan.user_id == user_id,
            Vulnerability.status == "open",
        )
    )
    resolved_findings = await db.scalar(
        select(func.count()).select_from(Vulnerability).join(Scan).where(
            Scan.user_id == user_id,
            Vulnerability.status == "resolved",
        )
    )
    ignored_findings = await db.scalar(
        select(func.count()).select_from(Vulnerability).join(Scan).where(
            Scan.user_id == user_id,
            Vulnerability.status == "ignored",
        )
    )

    github_connection_count = await db.scalar(
        select(func.count()).select_from(GitHubConnection).where(
            GitHubConnection.user_id == user_id,
            GitHubConnection.is_connected.is_(True),
        )
    )

    organizations_count = 0
    repositories_count = 0
    github_result = await db.execute(
        select(GitHubConnection).where(
            GitHubConnection.user_id == user_id,
            GitHubConnection.is_connected.is_(True),
        )
    )
    github_connections = github_result.scalars().all()
    for connection in github_connections:
        organizations_count += len(connection.organizations or [])
        repositories_count += len(connection.repositories or [])

    compliance_result = await db.execute(
        select(ComplianceCheck).join(Scan).where(Scan.user_id == user_id)
    )
    compliance_checks = compliance_result.scalars().all()
    compliance_score = None
    if compliance_checks:
        passed = sum(1 for item in compliance_checks if item.result == "pass")
        compliance_score = round((passed / len(compliance_checks)) * 100, 2)

    owasp_checks = [item for item in compliance_checks if item.standard == "owasp_top_10" or item.standard == "owasp_asvs"]
    nist_checks = [item for item in compliance_checks if item.standard == "nist"]
    cwe_checks = [item for item in compliance_checks if item.standard == "cwe"]

    def _score(items):
        return round((sum(1 for item in items if item.result == "pass") / len(items)) * 100, 2) if items else None

    cve_linked_findings = await db.scalar(
        select(func.count()).select_from(Vulnerability).join(Scan).where(
            Scan.user_id == user_id,
            Vulnerability.cve_id.isnot(None),
        )
    )

    final_audit = derive_final_audit_verdict(
        overall_score=avg_score or 0,
        compliance_score=compliance_score,
        critical_findings=sev_counts.get(Severity.CRITICAL.value, 0),
        high_findings=sev_counts.get(Severity.HIGH.value, 0),
        cve_count=cve_linked_findings or 0,
    )

    recent_reports_result = await db.execute(
        select(Scan)
        .where(Scan.user_id == user_id, Scan.status == ScanStatus.COMPLETED.value)
        .order_by(Scan.finished_at.desc())
        .limit(5)
    )
    recent_scans = recent_reports_result.scalars().all()
    recent_reports = []
    for scan in recent_scans:
        recent_reports.append({
            "id": str(scan.id),
            "name": f"Security Report — {scan.target}",
            "target": scan.target,
            "type": scan.type,
            "format": "PDF",
            "status": "ready",
            "date": scan.finished_at.strftime("%Y-%m-%d") if scan.finished_at else None,
        })

    recent_ai_conversations = []
    for scan in recent_scans:
        scan_vuln_count = await db.scalar(
            select(func.count()).select_from(Vulnerability).where(Vulnerability.scan_id == scan.id)
        )
        scan_critical = await db.scalar(
            select(func.count()).select_from(Vulnerability).where(
                Vulnerability.scan_id == scan.id,
                Vulnerability.severity == Severity.CRITICAL.value,
            )
        )
        scan_high = await db.scalar(
            select(func.count()).select_from(Vulnerability).where(
                Vulnerability.scan_id == scan.id,
                Vulnerability.severity == Severity.HIGH.value,
            )
        )
        scan_cves = await db.scalar(
            select(func.count()).select_from(Vulnerability).where(
                Vulnerability.scan_id == scan.id,
                Vulnerability.cve_id.isnot(None),
            )
        )
        scan_verdict = derive_final_audit_verdict(
            overall_score=scan.overall_score or 0,
            compliance_score=compliance_score,
            critical_findings=scan_critical or 0,
            high_findings=scan_high or 0,
            cve_count=scan_cves or 0,
        )
        recent_ai_conversations.append({
            "id": str(scan.id),
            "title": f"AI Audit Insight — {scan.target}",
            "summary": f"{scan_verdict['verdict']} verdict for {scan.target} with {scan_vuln_count or 0} findings and score {scan.overall_score or 0:.1f}/100.",
            "message": scan_verdict["reason"],
            "severity": scan_verdict["verdict"],
        })

    repository_status = []
    for connection in github_connections:
        for repo in (connection.repositories or [])[:10]:
            repository_status.append({
                "name": repo.get("full_name") or repo.get("name"),
                "branch": repo.get("default_branch"),
                "status": "connected" if connection.is_connected else "disconnected",
                "private": repo.get("private", False),
            })

    risk_heatmap = []
    for i in range(7):
        day = datetime.now(timezone.utc) - timedelta(days=i)
        start_of_day = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
        end_of_day = start_of_day + timedelta(days=1)
        count = await db.scalar(
            select(func.count()).select_from(Vulnerability).join(Scan).where(
                Scan.user_id == user_id,
                Vulnerability.created_at >= start_of_day,
                Vulnerability.created_at < end_of_day,
            )
        )
        risk_heatmap.append({"day": day.strftime("%a"), "findings": count or 0})

    recent_result = await db.execute(
        select(Scan)
        .where(Scan.user_id == user_id)
        .order_by(Scan.queued_at.desc())
        .limit(10)
    )
    recent_scans = []
    for s in recent_result.scalars().all():
        vuln_count = await db.scalar(
            select(func.count()).select_from(Vulnerability).where(Vulnerability.scan_id == s.id)
        )
        recent_scans.append({
            "scan_id": str(s.id),
            "target": s.target,
            "type": s.type,
            "status": s.status,
            "overall_score": s.overall_score,
            "vulnerability_count": vuln_count or 0,
            "queued_at": str(s.queued_at) if s.queued_at else None,
        })

    top_vulns_result = await db.execute(
        select(Vulnerability, Scan)
        .join(Scan, Vulnerability.scan_id == Scan.id)
        .where(Scan.user_id == user_id)
        .order_by(Vulnerability.created_at.desc())
        .limit(5)
    )
    top_vulnerabilities = []
    for vuln, scan in top_vulns_result.all():
        top_vulnerabilities.append({
            "id": str(vuln.id),
            "name": vuln.rule_id or "Security Finding",
            "severity": vuln.severity.lower(),
            "target": scan.target,
            "cve": vuln.cve_id or "N/A",
            "status": "open",
            "cvss": round((vuln.ml_score or 50) / 10, 1),
        })

    scan_trend = []
    for i in range(6, -1, -1):
        day = datetime.now(timezone.utc) - timedelta(days=i)
        day_str = day.strftime("%a")
        start_of_day = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
        end_of_day = start_of_day + timedelta(days=1)

        scans_count = await db.scalar(
            select(func.count()).select_from(Scan).where(
                Scan.user_id == user_id,
                Scan.queued_at >= start_of_day,
                Scan.queued_at < end_of_day,
            )
        )
        threats_count = await db.scalar(
            select(func.count()).select_from(Vulnerability).join(Scan).where(
                Scan.user_id == user_id,
                Vulnerability.created_at >= start_of_day,
                Vulnerability.created_at < end_of_day,
            )
        )
        scan_trend.append({
            "date": day_str,
            "scans": scans_count or 0,
            "threats": threats_count or 0,
        })

    return DashboardResponse(
        total_scans=total or 0,
        completed_scans=completed or 0,
        failed_scans=failed or 0,
        vulnerabilities_by_severity=sev_counts,
        recent_scans=recent_scans,
        average_risk_score=round(avg_score, 2) if avg_score else None,
        top_vulnerabilities=top_vulnerabilities,
        scan_trend=scan_trend,
        projects=(total or 0),
        repositories=repositories_count,
        organizations=organizations_count,
        open_findings=open_findings or 0,
        critical_findings=sev_counts.get(Severity.CRITICAL.value, 0),
        high_findings=sev_counts.get(Severity.HIGH.value, 0),
        medium_findings=sev_counts.get(Severity.MEDIUM.value, 0),
        low_findings=sev_counts.get(Severity.LOW.value, 0),
        resolved_findings=resolved_findings or 0,
        ignored_findings=ignored_findings or 0,
        compliance_score=compliance_score,
        owasp_score=_score(owasp_checks),
        nist_score=_score(nist_checks),
        cwe_score=_score(cwe_checks),
        final_audit_verdict=final_audit["verdict"],
        final_audit_reason=final_audit["reason"],
        certificate_health="Healthy" if sev_counts.get(Severity.CRITICAL.value, 0) == 0 else "Needs Attention",
        tls_health="Healthy" if sev_counts.get(Severity.HIGH.value, 0) == 0 else "Needs Attention",
        repository_status=repository_status,
        recent_reports=recent_reports,
        recent_ai_conversations=recent_ai_conversations,
        risk_heatmap=risk_heatmap,
    )
