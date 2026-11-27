import axios from 'axios';

export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').trim().replace(/\/+$/, '');
export const API_TIMEOUT_MS = Number(import.meta.env.VITE_API_TIMEOUT_MS) || 15000;
export const AUTH_MODE = (import.meta.env.VITE_AUTH_MODE || 'admin_key').trim().toLowerCase();

/**
 * Strictly in-memory session credential holder.
 * Never persisted to localStorage, sessionStorage, or cookies by the client.
 */
const memorySession = {
  adminKey: null,
  actor: null,
};

let unauthorizedHandler = null;

export function setMemoryCredentials({ adminKey, actor }) {
  memorySession.adminKey = adminKey ? String(adminKey).trim() : null;
  memorySession.actor = actor ? String(actor).trim() || null : null;
}

export function clearMemoryCredentials() {
  memorySession.adminKey = null;
  memorySession.actor = null;
}

export function hasMemoryCredentials() {
  if (AUTH_MODE === 'session_cookie') return true;
  return Boolean(memorySession.adminKey);
}

export function getMemoryActor() {
  return memorySession.actor;
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
  constructor(message, { status = 0, code = 'UNKNOWN_ERROR', correlationId = null, details = null, retryAfter = null } = {}) {
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
  withCredentials: AUTH_MODE === 'session_cookie',
});

apiClient.interceptors.request.use((config) => {
  if (AUTH_MODE === 'session_cookie') {
    config.withCredentials = true;
  } else if (!config.skipAuth && memorySession.adminKey) {
    config.headers = config.headers || {};
    if (!config.headers['X-Admin-Key']) {
      config.headers['X-Admin-Key'] = memorySession.adminKey;
    }
    if (memorySession.actor && !config.headers['X-Admin-Actor']) {
      config.headers['X-Admin-Actor'] = memorySession.actor;
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
