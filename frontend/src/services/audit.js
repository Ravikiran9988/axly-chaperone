import { apiClient, assertPaginatedResponse, cleanParams } from './api';

export async function listAuditEvents(params = {}) {
  const { data } = await apiClient.get('/api/v1/audit-events', {
    params: cleanParams(params),
  });
  return assertPaginatedResponse(data);
}

export async function getAuditEvent(eventId) {
  const { data } = await apiClient.get(`/api/v1/audit-events/${encodeURIComponent(eventId)}`);
  return data;
}
