from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..db import get_session
from ..models import Project, User
from ..schemas import ProjectIn, ProjectOut

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.get("", response_model=list[ProjectOut])
async def list_projects(
    user: User = Depends(current_user), session: AsyncSession = Depends(get_session)
) -> list[Project]:
    res = await session.execute(select(Project).where(Project.owner_id == user.id).order_by(Project.id.desc()))
    return list(res.scalars())


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
async def create_project(
    body: ProjectIn,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> Project:
    project = Project(name=body.name, description=body.description, owner_id=user.id)
    session.add(project)
    await session.commit()
    await session.refresh(project)
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: int,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    project = await session.get(Project, project_id)
    if not project or project.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    await session.delete(project)
    await session.commit()
