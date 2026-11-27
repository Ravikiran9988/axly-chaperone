"""Gateway evaluation and controlled execution endpoints."""

from __future__ import annotations

import json
import re
import uuid

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.database import get_db_session
from app.core.exceptions import BadRequestError
from app.models.agent import Agent
from app.schemas.gateway import (
    GatewayEvaluateRequest,
    GatewayEvaluateResponse,
    GatewayExecuteRequest,
    GatewayExecuteResponse,
)
from app.security.authentication import AgentAuthResult, get_agent_auth_result, resolve_settings
from app.services.gateway_service import GatewayService

router = APIRouter(prefix="/api/v1/gateway", tags=["Gateway"])
_gateway_service = GatewayService()
_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")


async def _extract_audit_summary_from_raw_body(request: Request) -> tuple[str, str, str]:
    """Safely extract best-effort tool_name/action/resource for unauthenticated audit logs."""
    try:
        raw_bytes = await request.body()
        if not raw_bytes or len(raw_bytes) > 16_384:
            return ("gateway", "evaluate", "api/v1/gateway/evaluate")
        parsed = json.loads(raw_bytes)
        if not isinstance(parsed, dict):
            return ("gateway", "evaluate", "api/v1/gateway/evaluate")
        tool_name = parsed.get("tool_name")
        action = parsed.get("action")
        resource = parsed.get("resource")
        return (
            tool_name.strip().lower()[:128]
            if isinstance(tool_name, str) and tool_name.strip()
            else "gateway",
            action.strip().lower()[:64]
            if isinstance(action, str) and action.strip()
            else "evaluate",
            resource.strip()[:1024]
            if isinstance(resource, str) and resource.strip()
            else "api/v1/gateway/evaluate",
        )
    except Exception:
        return ("gateway", "evaluate", "api/v1/gateway/evaluate")


async def require_audited_gateway_agent(
    request: Request,
    auth_result: AgentAuthResult = Depends(get_agent_auth_result),
    session: AsyncSession = Depends(get_db_session),
) -> Agent:
    """Authenticate an AI agent and persist an audit record even on failed/disabled auth."""
    correlation_id = getattr(request.state, "correlation_id", None) or str(uuid.uuid4())
    if not auth_result.authenticated or auth_result.agent is None:
        tool_name, action, resource = await _extract_audit_summary_from_raw_body(request)
        await _gateway_service.record_unauthenticated_attempt(
            session,
            auth_result=auth_result,
            correlation_id=correlation_id,
            tool_name=tool_name,
            action=action,
            resource=resource,
        )
    assert auth_result.agent is not None
    return auth_result.agent


@router.post(
    "/evaluate",
    response_model=GatewayEvaluateResponse,
    summary="Evaluate an AI agent tool request against deterministic security policies",
)
async def evaluate_gateway_request(
    request: Request,
    payload: GatewayEvaluateRequest,
    agent: Agent = Depends(require_audited_gateway_agent),
    session: AsyncSession = Depends(get_db_session),
) -> GatewayEvaluateResponse:
    """Evaluate tool access without executing the tool."""
    correlation_id = getattr(request.state, "correlation_id", None) or str(uuid.uuid4())
    return await _gateway_service.evaluate_request(
        session,
        agent=agent,
        payload=payload,
        correlation_id=correlation_id,
    )


@router.post(
    "/execute",
    response_model=GatewayExecuteResponse,
    summary="Evaluate policies, enforce approvals, execute controlled adapter, and verify outcome",
)
async def execute_gateway_request(
    request: Request,
    payload: GatewayExecuteRequest,
    agent: Agent = Depends(require_audited_gateway_agent),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(resolve_settings),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    """Controlled execution gateway enforcing policy, approvals, verification, and audit."""
    cleaned_idem: str | None = None
    if idempotency_key is not None:
        candidate = idempotency_key.strip()
        if not _IDEMPOTENCY_KEY_RE.fullmatch(candidate):
            raise BadRequestError(
                "Idempotency-Key must be 8-128 characters of [A-Za-z0-9._-].",
                code="INVALID_IDEMPOTENCY_KEY",
            )
        cleaned_idem = candidate

    correlation_id = getattr(request.state, "correlation_id", None) or str(uuid.uuid4())
    status_code, response_model = await _gateway_service.execute_request(
        session,
        agent=agent,
        payload=payload,
        correlation_id=correlation_id,
        settings=settings,
        idempotency_key=cleaned_idem,
    )
    return JSONResponse(
        status_code=status_code,
        content=response_model.model_dump(mode="json"),
        headers={"X-Correlation-ID": correlation_id},
    )
