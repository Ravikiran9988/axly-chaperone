import { apiClient, AUTH_MODE, clearMemoryCredentials, setMemoryCredentials } from './api';

/**
 * Verifies admin credentials directly against a protected backend endpoint.
 * Note: Phase 1/2 backend uses X-Admin-Key without a dedicated /auth/login route.
 * In session_cookie mode (Phase 4 contract), relies on existing HTTP-only session cookies.
 */
export async function authenticateAdminSession({ adminKey, actor } = {}) {
  const headers = {};
  if (AUTH_MODE !== 'session_cookie') {
    if (!adminKey || !adminKey.trim()) {
      throw new Error('Administrator API key is required.');
    }
    headers['X-Admin-Key'] = adminKey.trim();
    if (actor && actor.trim()) {
      headers['X-Admin-Actor'] = actor.trim();
    }
  }

  await apiClient.get('/api/v1/agents', {
    params: { page: 1, page_size: 1 },
    headers,
    skipAuth: AUTH_MODE !== 'session_cookie',
    suppressUnauthorizedHandler: true,
    withCredentials: AUTH_MODE === 'session_cookie',
  });

  if (AUTH_MODE !== 'session_cookie') {
    setMemoryCredentials({ adminKey, actor });
  }

  return {
    authenticated: true,
    authScheme: AUTH_MODE === 'session_cookie' ? 'http-only-cookie' : 'x-admin-key',
    actor: actor?.trim() || 'admin',
  };
}

export async function logoutAdminSession() {
  clearMemoryCredentials();
}
