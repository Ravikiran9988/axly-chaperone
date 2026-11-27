import { MemoryRouter } from 'react-router-dom';
import { QueryClient } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { AppProviders } from '../app/providers';
import { AppRouter } from '../app/router';
import { apiClient, setAuthSessionState } from '../services/api';

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
  let cookieSessionActive = false;

  apiClient.defaults.adapter = async (config) => {
    const method = (config.method || 'get').toUpperCase();
    const url = config.url || '';
    const params = config.params || {};
    const body = config.data ? JSON.parse(config.data) : null;
    const headers = config.headers || {};

    calls.push({ method, url, params, body, headers });

    let res = await handler({ method, url, params, body, headers, config });

    if (res === undefined) {
      if (url === '/api/v1/auth/session' && method === 'GET') {
        res = cookieSessionActive
          ? {
              status: 200,
              data: {
                authenticated: true,
                auth_scheme: 'session_cookie',
                reviewer_id: 'secops-lead',
                role: 'super_admin',
                csrf_token: 'csrf-test-token',
              },
            }
          : {
              status: 401,
              data: { error: { code: 'ADMIN_AUTH_REQUIRED', message: 'Administrative authentication required.' } },
            };
      } else if (url === '/api/v1/auth/login' && method === 'POST') {
        cookieSessionActive = true;
        res = {
          status: 200,
          data: {
            authenticated: true,
            auth_scheme: 'session_cookie',
            reviewer_id: body?.username || 'bootstrap-admin:mock',
            role: 'super_admin',
            csrf_token: 'csrf-test-token',
          },
        };
      } else if (url === '/api/v1/auth/logout' && method === 'POST') {
        cookieSessionActive = false;
        res = { status: 200, data: { logged_out: true } };
      } else {
        res = { data: paginated([]) };
      }
    }

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

export function renderApp({ route = '/', authenticated = false } = {}) {
  if (authenticated) {
    setAuthSessionState({ authenticated: true, csrfToken: 'csrf-test-token' });
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

export async function signInAsAdmin(user, { username = 'secops-lead', password = 'StrongTestPassword!123' } = {}) {
  const userInput = await screen.findByLabelText(/Administrator Username/i);
  await user.type(userInput, username);
  await user.type(screen.getByLabelText(/^Password$/i), password);
  await user.click(screen.getByRole('button', { name: /Sign In with Session Cookie/i }));
  await screen.findByRole('heading', { name: 'Overview' });
}
