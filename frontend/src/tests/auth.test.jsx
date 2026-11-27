import { describe, expect, it } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { installMockApiAdapter, paginated, renderApp, signInAsAdmin } from './testUtils';

describe('Authentication, cookie sessions, CSRF, and error handling', () => {
  it('authenticates via session cookie, attaches CSRF on state changes, never sends X-Admin-Actor, and signs out', async () => {
    const user = userEvent.setup();
    let loggedIn = false;

    const calls = installMockApiAdapter(({ method, url, body }) => {
      if (url === '/health') return { data: { status: 'ok', service: 'AXLY Chaperone', version: '0.1.0' } };
      if (url === '/ready') return { data: { status: 'ready', service: 'AXLY Chaperone', database: 'connected' } };
      if (url === '/api/v1/auth/session') {
        return loggedIn
          ? {
              data: {
                authenticated: true,
                auth_scheme: 'session_cookie',
                reviewer_id: 'secops-lead',
                role: 'super_admin',
                csrf_token: 'csrf-abc-123',
              },
            }
          : { status: 401, data: { error: { code: 'ADMIN_AUTH_REQUIRED', message: 'Auth required' } } };
      }
      if (url === '/api/v1/auth/login' && method === 'POST') {
        if (body?.username === 'secops-lead' && body?.password === 'ValidAdminPassword!123') {
          loggedIn = true;
          return {
            data: {
              authenticated: true,
              auth_scheme: 'session_cookie',
              reviewer_id: 'secops-lead',
              role: 'super_admin',
              csrf_token: 'csrf-abc-123',
            },
          };
        }
        return {
          status: 401,
          data: { error: { code: 'INVALID_ADMIN_CREDENTIALS', message: 'Invalid administrator username or password.' } },
        };
      }
      if (url === '/api/v1/auth/logout' && method === 'POST') {
        loggedIn = false;
        return { data: { logged_out: true } };
      }
      if (url.startsWith('/api/v1/')) return { data: paginated([]) };
      return { status: 404, data: {} };
    });

    renderApp({ route: '/login' });

    await user.type(await screen.findByLabelText(/Administrator Username/i), 'secops-lead');
    await user.type(screen.getByLabelText(/^Password$/i), 'wrong-password');
    await user.click(screen.getByRole('button', { name: /Sign In with Session Cookie/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/Invalid administrator username or password/i);

    await user.clear(screen.getByLabelText(/^Password$/i));
    await user.type(screen.getByLabelText(/^Password$/i), 'ValidAdminPassword!123');
    await user.click(screen.getByRole('button', { name: /Sign In with Session Cookie/i }));

    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument();
    const persistedStorage = JSON.stringify(window.localStorage);
    expect(persistedStorage).not.toContain('ValidAdminPassword');
    expect(persistedStorage).not.toContain('csrf-abc-123');
    expect(persistedStorage).not.toContain('secops-lead');
    expect(calls.every((c) => !c.headers['X-Admin-Actor'] && !c.headers['X-Admin-Key'])).toBe(true);

    // Sign out must send X-CSRF-Token automatically
    await user.click(screen.getByRole('button', { name: /secops-lead/i }));
    await user.click(screen.getByRole('button', { name: /Sign Out/i }));

    expect(await screen.findByRole('heading', { name: /Administrator Sign In/i })).toBeInTheDocument();
    const logoutCall = calls.find((c) => c.url === '/api/v1/auth/logout');
    expect(logoutCall?.headers['X-CSRF-Token']).toBe('csrf-abc-123');
  });

  it('rejects agent API keys entered into bootstrap admin key login immediately', async () => {
    const user = userEvent.setup();
    const calls = installMockApiAdapter(({ url }) => {
      if (url === '/health') return { data: { status: 'ok', service: 'AXLY Chaperone', version: '0.1.0' } };
      if (url === '/ready') return { data: { status: 'ready', service: 'AXLY Chaperone', database: 'connected' } };
      return undefined;
    });

    renderApp({ route: '/login' });
    await user.click(screen.getByRole('tab', { name: /Bootstrap Key/i }));
    await user.type(await screen.findByLabelText(/Bootstrap Admin Key/i), 'axly_ag_12345678_secret');
    await user.click(screen.getByRole('button', { name: /Authenticate Session/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/Agent API keys/i);
    expect(calls.some((c) => c.url === '/api/v1/auth/login')).toBe(false);
  });

  it('handles expired/rejected sessions (401) from protected API responses', async () => {
    const user = userEvent.setup();
    let rejectRequests = false;

    installMockApiAdapter(({ url }) => {
      if (url === '/health') return { data: { status: 'ok', service: 'AXLY Chaperone', version: '0.1.0' } };
      if (url === '/ready') return { data: { status: 'ready', service: 'AXLY Chaperone', database: 'connected' } };
      if (url === '/api/v1/agents') {
        if (rejectRequests) {
          return {
            status: 401,
            data: { error: { code: 'SESSION_EXPIRED', message: 'Administrative session has expired.' } },
          };
        }
        return { data: paginated([]) };
      }
      return undefined;
    });

    renderApp({ route: '/login' });
    await signInAsAdmin(user);

    rejectRequests = true;
    await user.click(screen.getByRole('link', { name: 'Agents' }));

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Administrator Sign In/i })).toBeInTheDocument();
    });
    expect(screen.getByRole('status')).toHaveTextContent(/session expired or was revoked/i);
  });

  it('displays structured API error states with retry when backend fails with 500', async () => {
    const user = userEvent.setup();
    let failAgents = true;

    installMockApiAdapter(({ url }) => {
      if (url === '/health') return { data: { status: 'ok', service: 'AXLY Chaperone', version: '0.1.0' } };
      if (url === '/ready') return { data: { status: 'ready', service: 'AXLY Chaperone', database: 'connected' } };
      if (url === '/api/v1/agents') {
        if (failAgents) {
          return {
            status: 500,
            data: { error: { code: 'INTERNAL_ERROR', message: 'Database query failed', correlation_id: 'cid-err-99' } },
          };
        }
        return { data: paginated([]) };
      }
      return undefined;
    });

    renderApp({ route: '/login' });
    failAgents = false;
    await signInAsAdmin(user);

    failAgents = true;
    await user.click(screen.getByRole('link', { name: 'Agents' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/Database query failed/i);
    expect(screen.getByRole('alert')).toHaveTextContent(/cid-err-99/i);

    failAgents = false;
    await user.click(screen.getByRole('button', { name: /Retry/i }));
    expect(await screen.findByText(/No agents registered yet/i)).toBeInTheDocument();
  });
});
