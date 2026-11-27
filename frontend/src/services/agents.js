import { apiClient, assertPaginatedResponse, cleanParams } from './api';

export async function listAgents(params = {}) {
  const { data } = await apiClient.get('/api/v1/agents', {
    params: cleanParams(params),
  });
  return assertPaginatedResponse(data);
}

export async function getAgent(agentId) {
  const { data } = await apiClient.get(`/api/v1/agents/${encodeURIComponent(agentId)}`);
  return data;
}

export async function registerAgent(payload) {
  const body = {
    name: payload.name.trim(),
    description: payload.description?.trim() || null,
  };
  const { data } = await apiClient.post('/api/v1/agents', body);
  return data;
}

export async function updateAgentStatus(agentId, status) {
  const { data } = await apiClient.patch(`/api/v1/agents/${encodeURIComponent(agentId)}/status`, {
    status,
  });
  return data;
}
