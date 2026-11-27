import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  clearAuthSessionState,
  hasMemoryCredentials,
  registerUnauthorizedHandler,
} from '../services/api';
import {
  fetchCurrentAdminSession,
  loginAdminSession,
  logoutAdminSession,
} from '../services/auth';

const IDLE_TIMEOUT_MS = 30 * 60 * 1000;

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState(hasMemoryCredentials() ? 'authenticated' : 'checking');
  const [user, setUser] = useState(null);
  const [sessionNotice, setSessionNotice] = useState(null);
  const idleTimerRef = useRef(null);

  const clearSessionState = useCallback(
    (notice = null) => {
      clearAuthSessionState();
      queryClient.clear();
      setUser(null);
      setStatus('unauthenticated');
      setSessionNotice(notice);
    },
    [queryClient]
  );

  const logout = useCallback(
    async (notice = null) => {
      await logoutAdminSession();
      clearSessionState(notice);
    },
    [clearSessionState]
  );

  const login = useCallback(async ({ username, password, adminKey } = {}) => {
    const sessionInfo = await loginAdminSession({ username, password, adminKey });
    setUser({
      reviewerId: sessionInfo.reviewerId,
      role: sessionInfo.role,
      authScheme: sessionInfo.authScheme,
      expiresAt: sessionInfo.expiresAt,
      authenticatedAt: new Date().toISOString(),
    });
    setSessionNotice(null);
    setStatus('authenticated');
    return sessionInfo;
  }, []);

  // Register global 401 / ADMIN_NOT_CONFIGURED handler on Axios client
  useEffect(() => {
    return registerUnauthorizedHandler((apiError) => {
      const notice =
        apiError.code === 'ADMIN_NOT_CONFIGURED'
          ? {
              type: 'error',
              message:
                'Backend administrative authentication is not configured. Create an admin user or set CHAPERONE_ADMIN_API_KEY.',
            }
          : {
              type: 'warning',
              message:
                apiError.code === 'SESSION_EXPIRED' || apiError.code === 'SESSION_REVOKED'
                  ? 'Your administrative session expired or was revoked. Please sign in again.'
                  : 'Your session expired or credentials were rejected. Please sign in again.',
            };
      clearSessionState(notice);
    });
  }, [clearSessionState]);

  // Verify active HttpOnly cookie session on initial load
  useEffect(() => {
    let cancelled = false;
    fetchCurrentAdminSession()
      .then((sessionInfo) => {
        if (cancelled) return;
        setUser({
          reviewerId: sessionInfo.reviewerId,
          role: sessionInfo.role,
          authScheme: sessionInfo.authScheme,
          expiresAt: sessionInfo.expiresAt,
          authenticatedAt: new Date().toISOString(),
        });
        setStatus('authenticated');
      })
      .catch(() => {
        if (cancelled) return;
        if (!hasMemoryCredentials()) {
          setStatus('unauthenticated');
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // In-memory inactivity lock timer
  useEffect(() => {
    if (status !== 'authenticated') {
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
      return undefined;
    }

    const resetIdleTimer = () => {
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
      idleTimerRef.current = setTimeout(() => {
        logout({
          type: 'warning',
          message: 'Session locked after 30 minutes of inactivity. Please re-authenticate.',
        });
      }, IDLE_TIMEOUT_MS);
    };

    resetIdleTimer();
    const events = ['pointerdown', 'keydown'];
    events.forEach((evt) => window.addEventListener(evt, resetIdleTimer, { passive: true }));

    return () => {
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
      events.forEach((evt) => window.removeEventListener(evt, resetIdleTimer));
    };
  }, [status, logout]);

  const clearNotice = useCallback(() => setSessionNotice(null), []);

  const value = useMemo(
    () => ({
      authMode: 'session_cookie',
      status,
      isChecking: status === 'checking',
      isAuthenticated: status === 'authenticated',
      user,
      canApprove: !user?.role || user.role === 'approver' || user.role === 'super_admin',
      canManageConfig: !user?.role || user.role === 'super_admin',
      sessionNotice,
      clearNotice,
      login,
      logout,
    }),
    [status, user, sessionNotice, clearNotice, login, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
