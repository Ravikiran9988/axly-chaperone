"""Administrative API endpoints for AI agent registration and lifecycle control."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.database import get_db_session
from app.models.enums import AgentStatus
from app.schemas.agent import (
    AgentCreateRequest,
    AgentCreateResponse,
    AgentResponse,
    AgentStatusUpdateRequest,
)
from app.schemas.common import PaginatedResponse
from app.security.authentication import AdminPrincipal, resolve_settings
from app.security.authorization import require_admin, require_super_admin
from app.services.agent_service import AgentService

router = APIRouter(
    prefix="/api/v1/agents",
    tags=["Agents"],
    dependencies=[Depends(require_admin)],
)
_agent_service = AgentService()


@router.post(
    "",
    response_model=AgentCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register an AI agent and issue its one-time API key",
)
async def register_agent(
    payload: AgentCreateRequest,
    _principal: AdminPrincipal = Depends(require_super_admin),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(resolve_settings),
) -> AgentCreateResponse:
    """Register a new AI agent. The raw API key is returned once and never stored plaintext."""
    agent, raw_key = await _agent_service.register_agent(session, payload, settings=settings)
    return AgentCreateResponse(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        key_prefix=agent.key_prefix,
        status=AgentStatus(agent.status),
        created_at=agent.created_at,
        updated_at=agent.updated_at,
        api_key=raw_key,
    )


@router.get(
    "",
    response_model=PaginatedResponse[AgentResponse],
    summary="List registered AI agents",
)
async def list_agents(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status_filter: AgentStatus | None = Query(default=None, alias="status"),
    session: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[AgentResponse]:
    """List registered agents with pagination (API keys and hashes are never returned)."""
    items, total = await _agent_service.list_agents(
        session,
        page=page,
        page_size=page_size,
        status_filter=status_filter,
    )
    return PaginatedResponse.create(
        items=[AgentResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{agent_id}",
    response_model=AgentResponse,
    summary="Get details for a registered AI agent",
)
async def get_agent(
    agent_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> AgentResponse:
    """Retrieve a single registered agent without exposing credential secrets."""
    agent = await _agent_service.get_agent(session, agent_id)
    return AgentResponse.model_validate(agent)


@router.patch(
    "/{agent_id}/status",
    response_model=AgentResponse,
    summary="Enable or disable an AI agent",
)
async def update_agent_status(
    agent_id: UUID,
    payload: AgentStatusUpdateRequest,
    _principal: AdminPrincipal = Depends(require_super_admin),
    session: AsyncSession = Depends(get_db_session),
) -> AgentResponse:
    """Activate or disable an agent immediately."""
    agent = await _agent_service.update_status(session, agent_id, payload.status)
    return AgentResponse.model_validate(agent)
