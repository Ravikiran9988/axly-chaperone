import { apiClient, assertPaginatedResponse, cleanParams } from './api';

export async function listPolicies(params = {}) {
  const { data } = await apiClient.get('/api/v1/policies', {
    params: cleanParams(params),
  });
  return assertPaginatedResponse(data);
}

export async function getPolicy(policyId) {
  const { data } = await apiClient.get(`/api/v1/policies/${encodeURIComponent(policyId)}`);
  return data;
}

export async function createPolicy(payload) {
  const body = {
    name: payload.name.trim(),
    description: payload.description?.trim() || null,
    agent_id: payload.agent_id ? payload.agent_id.trim() : null,
    tool_name: payload.tool_name.trim().toLowerCase(),
    action: payload.action.trim().toLowerCase(),
    resource_scope: payload.resource_scope.trim(),
    decision: payload.decision,
    enabled: Boolean(payload.enabled),
    priority: Number(payload.priority),
  };
  const { data } = await apiClient.post('/api/v1/policies', body);
  return data;
}

export async function updatePolicy(policyId, payload) {
  const body = cleanParams({
    description: payload.description !== undefined ? payload.description.trim() : undefined,
    action: payload.action !== undefined ? payload.action.trim().toLowerCase() : undefined,
    resource_scope: payload.resource_scope !== undefined ? payload.resource_scope.trim() : undefined,
    decision: payload.decision,
    enabled: payload.enabled,
    priority: payload.priority !== undefined ? Number(payload.priority) : undefined,
  });
  const { data } = await apiClient.patch(`/api/v1/policies/${encodeURIComponent(policyId)}`, body);
  return data;
}
