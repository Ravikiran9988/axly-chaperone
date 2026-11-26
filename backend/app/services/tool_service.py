"""Service layer for managing registered tool definitions."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError, ResourceNotFoundError
from app.models.enums import RiskLevel
from app.models.tool import Tool
from app.schemas.tool import ToolCreateRequest, ToolUpdateRequest


class ToolService:
    """Encapsulates tool registry CRUD operations (no tool execution in Phase 1)."""

    async def register_tool(self, session: AsyncSession, payload: ToolCreateRequest) -> Tool:
        """Register a new tool definition by unique name."""
        existing = await session.execute(select(Tool.id).where(Tool.name == payload.name))
        if existing.scalar_one_or_none() is not None:
            raise ConflictError(f"Tool '{payload.name}' is already registered.")

        tool = Tool(
            name=payload.name,
            description=payload.description,
            category=payload.category,
            risk_level=payload.risk_level.value,
            enabled=payload.enabled,
        )
        session.add(tool)
        try:
            await session.commit()
            await session.refresh(tool)
        except IntegrityError as exc:
            await session.rollback()
            raise ConflictError(f"Tool '{payload.name}' is already registered.") from exc
        return tool

    async def list_tools(
        self,
        session: AsyncSession,
        *,
        page: int,
        page_size: int,
        category: str | None = None,
        risk_level: RiskLevel | None = None,
        enabled: bool | None = None,
    ) -> tuple[list[Tool], int]:
        """List registered tools with pagination and optional filtering."""
        filters = []
        if category is not None:
            filters.append(Tool.category == category.strip().lower())
        if risk_level is not None:
            filters.append(Tool.risk_level == risk_level.value)
        if enabled is not None:
            filters.append(Tool.enabled.is_(enabled))

        count_stmt = select(func.count()).select_from(Tool).where(*filters)
        total = int((await session.execute(count_stmt)).scalar_one())

        offset = (page - 1) * page_size
        stmt = (
            select(Tool).where(*filters).order_by(Tool.name.asc()).offset(offset).limit(page_size)
        )
        items = list((await session.execute(stmt)).scalars().all())
        return items, total

    async def get_tool_by_name(self, session: AsyncSession, tool_name: str) -> Tool:
        """Retrieve a tool definition by unique name or raise ResourceNotFoundError."""
        normalized = tool_name.strip().lower()
        stmt = select(Tool).where(Tool.name == normalized)
        tool = (await session.execute(stmt)).scalar_one_or_none()
        if tool is None:
            raise ResourceNotFoundError(f"Tool '{normalized}' not found.")
        return tool

    async def update_tool(
        self,
        session: AsyncSession,
        tool_name: str,
        payload: ToolUpdateRequest,
    ) -> Tool:
        """Update mutable properties on a registered tool."""
        tool = await self.get_tool_by_name(session, tool_name)
        if payload.description is not None:
            tool.description = payload.description
        if payload.category is not None:
            tool.category = payload.category
        if payload.risk_level is not None:
            tool.risk_level = payload.risk_level.value
        if payload.enabled is not None:
            tool.enabled = payload.enabled

        await session.commit()
        await session.refresh(tool)
        return tool
