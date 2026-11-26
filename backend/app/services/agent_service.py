"""Service layer for AI agent registration, retrieval, and lifecycle management."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.exceptions import ConflictError, ResourceNotFoundError
from app.core.security import generate_agent_api_key
from app.models.agent import Agent
from app.models.enums import AgentStatus
from app.schemas.agent import AgentCreateRequest


class AgentService:
    """Encapsulates agent persistence and credential lifecycle operations."""

    async def register_agent(
        self,
        session: AsyncSession,
        payload: AgentCreateRequest,
        *,
        settings: Settings,
    ) -> tuple[Agent, str]:
        """Register a new agent and return (Agent, one_time_raw_api_key)."""
        existing = await session.execute(select(Agent.id).where(Agent.name == payload.name))
        if existing.scalar_one_or_none() is not None:
            raise ConflictError(f"Agent with name '{payload.name}' already exists.")

        generated = generate_agent_api_key(
            iterations=settings.api_key_hash_iterations,
            pepper=settings.get_api_key_pepper(),
        )
        agent = Agent(
            name=payload.name,
            description=payload.description,
            key_id=generated.key_id,
            key_prefix=generated.key_prefix,
            api_key_hash=generated.key_hash,
            status=AgentStatus.ACTIVE.value,
        )
        session.add(agent)
        try:
            await session.commit()
            await session.refresh(agent)
        except IntegrityError as exc:
            await session.rollback()
            raise ConflictError(f"Agent with name '{payload.name}' already exists.") from exc

        return agent, generated.raw_key

    async def list_agents(
        self,
        session: AsyncSession,
        *,
        page: int,
        page_size: int,
        status_filter: AgentStatus | None = None,
    ) -> tuple[list[Agent], int]:
        """List registered agents with pagination and optional status filter."""
        filters = []
        if status_filter is not None:
            filters.append(Agent.status == status_filter.value)

        count_stmt = select(func.count()).select_from(Agent).where(*filters)
        total = int((await session.execute(count_stmt)).scalar_one())

        offset = (page - 1) * page_size
        stmt = (
            select(Agent)
            .where(*filters)
            .order_by(Agent.created_at.desc(), Agent.id.asc())
            .offset(offset)
            .limit(page_size)
        )
        items = list((await session.execute(stmt)).scalars().all())
        return items, total

    async def get_agent(self, session: AsyncSession, agent_id: UUID) -> Agent:
        """Retrieve a registered agent by UUID or raise ResourceNotFoundError."""
        stmt = select(Agent).where(Agent.id == agent_id)
        agent = (await session.execute(stmt)).scalar_one_or_none()
        if agent is None:
            raise ResourceNotFoundError(f"Agent '{agent_id}' not found.")
        return agent

    async def update_status(
        self,
        session: AsyncSession,
        agent_id: UUID,
        new_status: AgentStatus,
    ) -> Agent:
        """Enable or disable a registered agent."""
        agent = await self.get_agent(session, agent_id)
        agent.status = new_status.value
        await session.commit()
        await session.refresh(agent)
        return agent
