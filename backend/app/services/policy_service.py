"""Service layer for managing authorization policies."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError, ResourceNotFoundError
from app.models.agent import Agent
from app.models.enums import PolicyDecision
from app.models.policy import Policy
from app.models.tool import Tool
from app.schemas.policy import PolicyCreateRequest, PolicyUpdateRequest


class PolicyService:
    """Encapsulates creation, retrieval, listing, and versioned updates of policies."""

    async def create_policy(self, session: AsyncSession, payload: PolicyCreateRequest) -> Policy:
        """Create a deterministic authorization policy referencing a registered tool."""
        tool_exists = await session.execute(select(Tool.id).where(Tool.name == payload.tool_name))
        if tool_exists.scalar_one_or_none() is None:
            raise ResourceNotFoundError(
                f"Cannot create policy for unregistered tool '{payload.tool_name}'."
            )

        if payload.agent_id is not None:
            agent_exists = await session.execute(
                select(Agent.id).where(Agent.id == payload.agent_id)
            )
            if agent_exists.scalar_one_or_none() is None:
                raise ResourceNotFoundError(f"Agent '{payload.agent_id}' not found.")

        existing = await session.execute(select(Policy.id).where(Policy.name == payload.name))
        if existing.scalar_one_or_none() is not None:
            raise ConflictError(f"Policy with name '{payload.name}' already exists.")

        policy = Policy(
            name=payload.name,
            description=payload.description,
            agent_id=payload.agent_id,
            tool_name=payload.tool_name,
            action=payload.action,
            resource_scope=payload.resource_scope,
            decision=payload.decision.value,
            enabled=payload.enabled,
            priority=payload.priority,
            version=1,
        )
        session.add(policy)
        try:
            await session.commit()
            await session.refresh(policy)
        except IntegrityError as exc:
            await session.rollback()
            raise ConflictError(f"Policy '{payload.name}' conflicts with existing policy.") from exc
        return policy

    async def list_policies(
        self,
        session: AsyncSession,
        *,
        page: int,
        page_size: int,
        agent_id: UUID | None = None,
        tool_name: str | None = None,
        decision: PolicyDecision | None = None,
        enabled: bool | None = None,
    ) -> tuple[list[Policy], int]:
        """List policies with pagination and optional filtering."""
        filters = []
        if agent_id is not None:
            filters.append(Policy.agent_id == agent_id)
        if tool_name is not None:
            filters.append(Policy.tool_name == tool_name.strip().lower())
        if decision is not None:
            filters.append(Policy.decision == decision.value)
        if enabled is not None:
            filters.append(Policy.enabled.is_(enabled))

        count_stmt = select(func.count()).select_from(Policy).where(*filters)
        total = int((await session.execute(count_stmt)).scalar_one())

        offset = (page - 1) * page_size
        stmt = (
            select(Policy)
            .where(*filters)
            .order_by(Policy.priority.desc(), Policy.created_at.desc(), Policy.id.asc())
            .offset(offset)
            .limit(page_size)
        )
        items = list((await session.execute(stmt)).scalars().all())
        return items, total

    async def get_policy(self, session: AsyncSession, policy_id: UUID) -> Policy:
        """Retrieve a policy by UUID or raise ResourceNotFoundError."""
        stmt = select(Policy).where(Policy.id == policy_id)
        policy = (await session.execute(stmt)).scalar_one_or_none()
        if policy is None:
            raise ResourceNotFoundError(f"Policy '{policy_id}' not found.")
        return policy

    async def update_policy(
        self,
        session: AsyncSession,
        policy_id: UUID,
        payload: PolicyUpdateRequest,
    ) -> Policy:
        """Update mutable policy fields and increment the policy version."""
        policy = await self.get_policy(session, policy_id)
        if payload.description is not None:
            policy.description = payload.description
        if payload.action is not None:
            policy.action = payload.action
        if payload.resource_scope is not None:
            policy.resource_scope = payload.resource_scope
        if payload.decision is not None:
            policy.decision = payload.decision.value
        if payload.enabled is not None:
            policy.enabled = payload.enabled
        if payload.priority is not None:
            policy.priority = payload.priority

        policy.version += 1
        await session.commit()
        await session.refresh(policy)
        return policy
