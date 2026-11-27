import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  AUTH_MODE,
  clearMemoryCredentials,
  registerUnauthorizedHandler,
} from '../services/api';
import { authenticateAdminSession, logoutAdminSession } from '../services/auth';

const IDLE_TIMEOUT_MS = 30 * 60 * 1000;

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState(
    AUTH_MODE === 'session_cookie' ? 'checking' : 'unauthenticated'
  );
  const [user, setUser] = useState(null);
  const [sessionNotice, setSessionNotice] = useState(null);
  const idleTimerRef = useRef(null);

  const clearSessionState = useCallback(
    (notice = null) => {
      clearMemoryCredentials();
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

  const login = useCallback(async ({ adminKey, actor } = {}) => {
    const sessionInfo = await authenticateAdminSession({ adminKey, actor });
    setUser({
      actor: sessionInfo.actor,
      authScheme: sessionInfo.authScheme,
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
                'Backend administrative authentication is not configured (CHAPERONE_ADMIN_API_KEY missing).',
            }
          : {
              type: 'warning',
              message: 'Your session expired or credentials were rejected. Please sign in again.',
            };
      clearSessionState(notice);
    });
  }, [clearSessionState]);

  // Optional Phase 4 HTTP-only cookie bootstrap check
  useEffect(() => {
    if (AUTH_MODE !== 'session_cookie') return;
    let cancelled = false;
    authenticateAdminSession()
      .then((sessionInfo) => {
        if (cancelled) return;
        setUser({
          actor: sessionInfo.actor,
          authScheme: sessionInfo.authScheme,
          authenticatedAt: new Date().toISOString(),
        });
        setStatus('authenticated');
      })
      .catch(() => {
        if (cancelled) return;
        setStatus('unauthenticated');
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
        clearSessionState({
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
  }, [status, clearSessionState]);

  const clearNotice = useCallback(() => setSessionNotice(null), []);

  const value = useMemo(
    () => ({
      authMode: AUTH_MODE,
      status,
      isChecking: status === 'checking',
      isAuthenticated: status === 'authenticated',
      user,
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
