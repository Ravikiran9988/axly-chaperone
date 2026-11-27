import axios from 'axios';

export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').trim().replace(/\/+$/, '');
export const API_TIMEOUT_MS = Number(import.meta.env.VITE_API_TIMEOUT_MS) || 15000;

/**
 * In-memory CSRF token + authentication state only.
 * Browser credentials stay inside the server-issued HttpOnly chaperone_session cookie —
 * never persisted in localStorage, sessionStorage, or exposed as long-lived admin secrets.
 */
const memorySession = {
  authenticated: false,
  csrfToken: null,
};

let unauthorizedHandler = null;

function readCookie(name) {
  if (typeof document === 'undefined' || !document.cookie) return null;
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = document.cookie.match(new RegExp(`(?:^|;\\s*)${escaped}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

export function setAuthSessionState({ authenticated = true, csrfToken = null } = {}) {
  memorySession.authenticated = Boolean(authenticated);
  memorySession.csrfToken = csrfToken || readCookie('chaperone_csrf') || null;
}

export function clearAuthSessionState() {
  memorySession.authenticated = false;
  memorySession.csrfToken = null;
}

// Preserve backwards-compatible helper name for any existing UI/test imports
export function clearMemoryCredentials() {
  clearAuthSessionState();
}

export function hasMemoryCredentials() {
  return memorySession.authenticated;
}

export function getCsrfToken() {
  return memorySession.csrfToken || readCookie('chaperone_csrf') || null;
}

export function registerUnauthorizedHandler(fn) {
  unauthorizedHandler = fn;
  return () => {
    if (unauthorizedHandler === fn) {
      unauthorizedHandler = null;
    }
  };
}

export class ApiError extends Error {
  constructor(
    message,
    { status = 0, code = 'UNKNOWN_ERROR', correlationId = null, details = null, retryAfter = null } = {}
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.correlationId = correlationId;
    this.details = details;
    this.retryAfter = retryAfter;
  }
}

export function cleanParams(params = {}) {
  const cleaned = {};
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      cleaned[key] = value;
    }
  }
  return cleaned;
}

export function assertPaginatedResponse(data) {
  if (!data || !Array.isArray(data.items) || typeof data.total !== 'number') {
    throw new ApiError('Unexpected response shape from backend API.', {
      code: 'INVALID_RESPONSE_SHAPE',
      status: 500,
    });
  }
  return data;
}

export function normalizeApiError(error) {
  if (error instanceof ApiError) {
    return error;
  }

  if (error?.code === 'ECONNABORTED') {
    return new ApiError('Request timed out while communicating with the Chaperone gateway.', {
      status: 0,
      code: 'REQUEST_TIMEOUT',
    });
  }

  if (!error?.response) {
    return new ApiError(
      'Unable to reach the AXLY Chaperone backend. Verify the server is running and CORS/proxy settings allow access.',
      {
        status: 0,
        code: 'NETWORK_ERROR',
      }
    );
  }

  const { status, data, headers } = error.response;
  const errObj = data?.error;
  const correlationId = errObj?.correlation_id || headers?.['x-correlation-id'] || null;
  const retryAfter = headers?.['retry-after'] ? Number(headers['retry-after']) : null;

  let message = errObj?.message || data?.detail || error.message || 'An unexpected error occurred.';
  if (errObj?.details && Array.isArray(errObj.details) && errObj.details.length > 0) {
    const firstDetail = errObj.details[0]?.msg;
    if (firstDetail) {
      message = `${message} (${firstDetail})`;
    }
  }

  return new ApiError(message, {
    status,
    code: errObj?.code || `HTTP_${status}`,
    correlationId,
    details: errObj?.details || null,
    retryAfter,
  });
}

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: API_TIMEOUT_MS,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
});

const UNSAFE_HTTP_METHODS = new Set(['post', 'put', 'patch', 'delete']);

apiClient.interceptors.request.use((config) => {
  config.withCredentials = true;
  const method = (config.method || 'get').toLowerCase();
  if (!config.skipCsrf && UNSAFE_HTTP_METHODS.has(method)) {
    const csrf = getCsrfToken();
    if (csrf) {
      config.headers = config.headers || {};
      config.headers['X-CSRF-Token'] = csrf;
    }
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const normalized = normalizeApiError(error);
    const config = error?.config || {};

    if (
      !config.suppressUnauthorizedHandler &&
      (normalized.status === 401 || normalized.code === 'ADMIN_NOT_CONFIGURED') &&
      typeof unauthorizedHandler === 'function'
    ) {
      unauthorizedHandler(normalized);
    }

    return Promise.reject(normalized);
  }
);
