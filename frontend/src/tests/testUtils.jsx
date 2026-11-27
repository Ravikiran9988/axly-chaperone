import { MemoryRouter } from 'react-router-dom';
import { QueryClient } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import { AppProviders } from '../app/providers';
import { AppRouter } from '../app/router';
import { apiClient, setMemoryCredentials } from '../services/api';

export function paginated(items, page = 1, pageSize = 20, totalOverride) {
  const total = totalOverride ?? items.length;
  return {
    items,
    total,
    page,
    page_size: pageSize,
    total_pages: total > 0 ? Math.ceil(total / pageSize) : 0,
  };
}

export function installMockApiAdapter(handler) {
  const calls = [];
  apiClient.defaults.adapter = async (config) => {
    const method = (config.method || 'get').toUpperCase();
    const url = config.url || '';
    const params = config.params || {};
    const body = config.data ? JSON.parse(config.data) : null;
    const headers = config.headers || {};

    calls.push({ method, url, params, body, headers });

    const res = await handler({ method, url, params, body, headers, config });
    const status = res?.status ?? 200;
    const data = res?.data ?? {};

    if (status >= 400) {
      const error = new Error(data?.error?.message || `HTTP ${status}`);
      error.config = config;
      error.response = {
        status,
        data,
        headers: res?.headers || {},
        config,
      };
      throw error;
    }

    return {
      data,
      status,
      statusText: 'OK',
      headers: res?.headers || {},
      config,
    };
  };
  return calls;
}

export function renderApp({ route = '/', adminKey = null, actor = null } = {}) {
  if (adminKey) {
    setMemoryCredentials({ adminKey, actor });
  }
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  const view = render(
    <MemoryRouter
      initialEntries={[route]}
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      <AppProviders queryClient={queryClient}>
        <AppRouter />
      </AppProviders>
    </MemoryRouter>
  );

  return { ...view, queryClient };
}
