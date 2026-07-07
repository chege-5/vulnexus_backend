import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db
from app.models.db_models import Organization, OrganizationMember, Project, User
from app.rate_limit import limiter
from app.services.rbac import Permission, require_permission

router = APIRouter()


class OrganizationCreateRequest(BaseModel):
    name: str


class ProjectCreateRequest(BaseModel):
    name: str
    description: str = ""
    organization_id: uuid.UUID | None = None


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or uuid.uuid4().hex[:8]


@router.get("/organizations")
@limiter.limit("20/minute")
async def list_organizations(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ORG_READ)),
):
    result = await db.execute(
        select(Organization)
        .outerjoin(OrganizationMember, OrganizationMember.organization_id == Organization.id)
        .where((Organization.owner_id == current_user.id) | (OrganizationMember.user_id == current_user.id))
        .order_by(Organization.created_at.desc())
    )
    organizations = result.scalars().unique().all()
    return [{"id": str(org.id), "name": org.name, "slug": org.slug, "owner_id": str(org.owner_id) if org.owner_id else None, "created_at": org.created_at.isoformat()} for org in organizations]


@router.post("/organizations")
@limiter.limit("10/minute")
async def create_organization(
    body: OrganizationCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ORG_WRITE)),
):
    org = Organization(name=body.name, slug=f"{_slug(body.name)}-{uuid.uuid4().hex[:6]}", owner_id=current_user.id)
    db.add(org)
    await db.flush()
    db.add(OrganizationMember(organization_id=org.id, user_id=current_user.id, role=current_user.role))
    await db.commit()
    return {"id": str(org.id), "name": org.name, "slug": org.slug}


@router.get("/projects")
@limiter.limit("20/minute")
async def list_projects(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ORG_READ)),
):
    result = await db.execute(
        select(Project)
        .outerjoin(Organization, Project.organization_id == Organization.id)
        .outerjoin(OrganizationMember, OrganizationMember.organization_id == Organization.id)
        .where((Project.owner_id == current_user.id) | (Organization.owner_id == current_user.id) | (OrganizationMember.user_id == current_user.id))
        .order_by(Project.created_at.desc())
    )
    projects = result.scalars().unique().all()
    return [{"id": str(project.id), "name": project.name, "slug": project.slug, "description": project.description, "organization_id": str(project.organization_id) if project.organization_id else None, "created_at": project.created_at.isoformat()} for project in projects]


@router.post("/projects")
@limiter.limit("10/minute")
async def create_project(
    body: ProjectCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ORG_WRITE)),
):
    if body.organization_id:
        membership = await db.execute(
            select(OrganizationMember).where(OrganizationMember.organization_id == body.organization_id, OrganizationMember.user_id == current_user.id)
        )
        owned = await db.execute(select(Organization).where(Organization.id == body.organization_id, Organization.owner_id == current_user.id))
        if not membership.scalar_one_or_none() and not owned.scalar_one_or_none():
            raise HTTPException(status_code=403, detail="Access denied for organization")

    project = Project(
        organization_id=body.organization_id,
        owner_id=current_user.id,
        name=body.name,
        slug=f"{_slug(body.name)}-{uuid.uuid4().hex[:6]}",
        description=body.description,
    )
    db.add(project)
    await db.commit()
    return {"id": str(project.id), "name": project.name, "slug": project.slug, "description": project.description, "organization_id": str(project.organization_id) if project.organization_id else None}
