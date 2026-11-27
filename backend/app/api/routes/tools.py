"""Administrative API endpoints for the Tool Registry."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.models.enums import RiskLevel
from app.schemas.common import PaginatedResponse
from app.schemas.tool import ToolCreateRequest, ToolResponse, ToolUpdateRequest
from app.security.authentication import AdminPrincipal
from app.security.authorization import require_admin, require_super_admin
from app.services.tool_service import ToolService

router = APIRouter(
    prefix="/api/v1/tools",
    tags=["Tools"],
    dependencies=[Depends(require_admin)],
)
_tool_service = ToolService()


@router.post(
    "",
    response_model=ToolResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a tool definition",
)
async def register_tool(
    payload: ToolCreateRequest,
    _principal: AdminPrincipal = Depends(require_super_admin),
    session: AsyncSession = Depends(get_db_session),
) -> ToolResponse:
    """Register a tool definition in the Chaperone Tool Registry (evaluation-only in Phase 1)."""
    tool = await _tool_service.register_tool(session, payload)
    return ToolResponse.model_validate(tool)


@router.get(
    "",
    response_model=PaginatedResponse[ToolResponse],
    summary="List registered tools",
)
async def list_tools(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    category: str | None = Query(default=None),
    risk_level: RiskLevel | None = Query(default=None),
    enabled: bool | None = Query(default=None),
    session: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[ToolResponse]:
    """List registered tool definitions with pagination and optional filters."""
    items, total = await _tool_service.list_tools(
        session,
        page=page,
        page_size=page_size,
        category=category,
        risk_level=risk_level,
        enabled=enabled,
    )
    return PaginatedResponse.create(
        items=[ToolResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{tool_name}",
    response_model=ToolResponse,
    summary="Get a registered tool by name",
)
async def get_tool(
    tool_name: str,
    session: AsyncSession = Depends(get_db_session),
) -> ToolResponse:
    """Retrieve a registered tool definition by unique tool name."""
    tool = await _tool_service.get_tool_by_name(session, tool_name)
    return ToolResponse.model_validate(tool)


@router.patch(
    "/{tool_name}",
    response_model=ToolResponse,
    summary="Update a registered tool definition",
)
async def update_tool(
    tool_name: str,
    payload: ToolUpdateRequest,
    _principal: AdminPrincipal = Depends(require_super_admin),
    session: AsyncSession = Depends(get_db_session),
) -> ToolResponse:
    """Enable/disable or update metadata of a registered tool."""
    tool = await _tool_service.update_tool(session, tool_name, payload)
    return ToolResponse.model_validate(tool)
