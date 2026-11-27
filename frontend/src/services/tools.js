import { apiClient, assertPaginatedResponse, cleanParams } from './api';

export async function listTools(params = {}) {
  const { data } = await apiClient.get('/api/v1/tools', {
    params: cleanParams(params),
  });
  return assertPaginatedResponse(data);
}

export async function getTool(toolName) {
  const { data } = await apiClient.get(`/api/v1/tools/${encodeURIComponent(toolName)}`);
  return data;
}

export async function registerTool(payload) {
  const body = {
    name: payload.name.trim().toLowerCase(),
    description: payload.description.trim(),
    category: payload.category.trim().toLowerCase(),
    risk_level: payload.risk_level,
    enabled: Boolean(payload.enabled),
  };
  const { data } = await apiClient.post('/api/v1/tools', body);
  return data;
}

export async function updateTool(toolName, payload) {
  const body = cleanParams({
    description: payload.description !== undefined ? payload.description.trim() : undefined,
    category: payload.category !== undefined ? payload.category.trim().toLowerCase() : undefined,
    risk_level: payload.risk_level,
    enabled: payload.enabled,
  });
  const { data } = await apiClient.patch(`/api/v1/tools/${encodeURIComponent(toolName)}`, body);
  return data;
}
