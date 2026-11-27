import { apiClient, clearAuthSessionState, setAuthSessionState } from './api';

/**
 * Exchange username/password (or explicit bootstrap demo key) for a short-lived
 * HttpOnly server-managed cookie session + CSRF synchronizer token.
 * Client-supplied X-Admin-Actor headers are never sent; reviewer identity is
 * derived exclusively server-side.
 */
export async function loginAdminSession({ username, password, adminKey } = {}) {
  const payload =
    adminKey && adminKey.trim()
      ? { admin_key: adminKey.trim() }
      : { username: username?.trim(), password };

  const res = await apiClient.post('/api/v1/auth/login', payload, {
    skipCsrf: true,
    suppressUnauthorizedHandler: true,
    withCredentials: true,
  });

  const data = res.data || {};
  setAuthSessionState({ authenticated: true, csrfToken: data.csrf_token });
  return {
    authenticated: true,
    authScheme: data.auth_scheme || 'session_cookie',
    reviewerId: data.reviewer_id || 'admin',
    role: data.role || 'super_admin',
    expiresAt: data.expires_at || null,
  };
}

export async function fetchCurrentAdminSession() {
  const res = await apiClient.get('/api/v1/auth/session', {
    suppressUnauthorizedHandler: true,
    withCredentials: true,
  });
  const data = res.data || {};
  setAuthSessionState({ authenticated: true, csrfToken: data.csrf_token });
  return {
    authenticated: true,
    authScheme: data.auth_scheme || 'session_cookie',
    reviewerId: data.reviewer_id || 'admin',
    role: data.role || 'super_admin',
    expiresAt: data.expires_at || null,
  };
}

export async function logoutAdminSession() {
  try {
    await apiClient.post(
      '/api/v1/auth/logout',
      {},
      {
        suppressUnauthorizedHandler: true,
        withCredentials: true,
      }
    );
  } catch {
    // Session may already be expired/revoked server-side; still clear client state
  } finally {
    clearAuthSessionState();
  }
}
