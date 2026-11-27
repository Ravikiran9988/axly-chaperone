import { apiClient, assertPaginatedResponse, cleanParams } from './api';

export async function listApprovals(params = {}) {
  const { data } = await apiClient.get('/api/v1/approvals', {
    params: cleanParams(params),
  });
  return assertPaginatedResponse(data);
}

export async function getApproval(approvalId) {
  const { data } = await apiClient.get(`/api/v1/approvals/${encodeURIComponent(approvalId)}`);
  return data;
}

export async function approveRequest(approvalId, { comment, executeNow = true } = {}) {
  const body = {
    comment: comment?.trim() || null,
    execute_now: Boolean(executeNow),
  };
  const { data } = await apiClient.post(
    `/api/v1/approvals/${encodeURIComponent(approvalId)}/approve`,
    body
  );
  return data;
}

export async function rejectRequest(approvalId, { comment } = {}) {
  const body = {
    comment: comment?.trim() || null,
  };
  const { data } = await apiClient.post(
    `/api/v1/approvals/${encodeURIComponent(approvalId)}/reject`,
    body
  );
  return data;
}
