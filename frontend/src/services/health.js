import { apiClient } from './api';

export async function getHealthStatus() {
  const start = performance.now();
  const { data } = await apiClient.get('/health', {
    skipAuth: true,
    suppressUnauthorizedHandler: true,
  });
  const latencyMs = Math.round(performance.now() - start);
  return { ...data, latencyMs };
}

export async function getReadinessStatus() {
  try {
    const { data } = await apiClient.get('/ready', {
      skipAuth: true,
      suppressUnauthorizedHandler: true,
    });
    return { ...data, httpStatus: 200 };
  } catch (err) {
    if (err.status === 503) {
      return {
        status: 'not_ready',
        service: 'AXLY Chaperone',
        database: 'unavailable',
        httpStatus: 503,
      };
    }
    throw err;
  }
}
