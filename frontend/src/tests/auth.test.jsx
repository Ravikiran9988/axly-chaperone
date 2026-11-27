import { describe, expect, it } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { installMockApiAdapter, paginated, renderApp } from './testUtils';
import { setMemoryCredentials } from '../services/api';

describe('Authentication and API error handling', () => {
  it('validates login, verifies admin key against backend, and signs out cleanly', async () => {
    const user = userEvent.setup();
    const calls = installMockApiAdapter(({ method, url, headers }) => {
      if (url === '/health') return { data: { status: 'ok', service: 'AXLY Chaperone', version: '0.1.0' } };
      if (url === '/ready') return { data: { status: 'ready', service: 'AXLY Chaperone', database: 'connected' } };
      if (method === 'GET' && url === '/api/v1/agents') {
        if (headers['X-Admin-Key'] === 'axly_adm_valid_secret_0123456789abcdef') {
          return { data: paginated([]) };
        }
        return {
          status: 401,
          data: { error: { code: 'INVALID_ADMIN_CREDENTIALS', message: 'Invalid administrative credentials.' } },
        };
      }
      if (url.startsWith('/api/v1/')) return { data: paginated([]) };
      return { status: 404, data: {} };
    });

    renderApp({ route: '/login' });

    const keyInput = screen.getByLabelText(/Admin API Key/i);
    await user.type(keyInput, 'wrong-key');
    await user.click(screen.getByRole('button', { name: /Authenticate Session/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/Invalid administrative credentials/i);
    expect(window.localStorage.getItem('X-Admin-Key')).toBeNull();

    await user.clear(keyInput);
    await user.type(keyInput, 'axly_adm_valid_secret_0123456789abcdef');
    await user.click(screen.getByRole('button', { name: /Authenticate Session/i }));

    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument();
    expect(calls.some((c) => c.headers['X-Admin-Key'] === 'axly_adm_valid_secret_0123456789abcdef')).toBe(true);
    expect(window.localStorage.getItem('axly_adm_valid_secret_0123456789abcdef')).toBeNull();

    // Sign out
    await user.click(screen.getByRole('button', { name: /admin/i }));
    await user.click(screen.getByRole('button', { name: /Sign Out/i }));

    expect(await screen.findByRole('heading', { name: /Administrator Sign In/i })).toBeInTheDocument();
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
            data: { error: { code: 'INVALID_ADMIN_CREDENTIALS', message: 'Key rotated' } },
          };
        }
        return { data: paginated([]) };
      }
      return { data: paginated([]) };
    });

    renderApp({ route: '/login' });
    await user.type(screen.getByLabelText(/Admin API Key/i), 'axly_adm_valid_key');
    await user.click(screen.getByRole('button', { name: /Authenticate Session/i }));
    await screen.findByRole('heading', { name: 'Overview' });

    rejectRequests = true;
    await user.click(screen.getByRole('link', { name: 'Agents' }));

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Administrator Sign In/i })).toBeInTheDocument();
    });
    expect(screen.getByRole('status')).toHaveTextContent(/session expired or credentials were rejected/i);
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
      return { data: paginated([]) };
    });

    setMemoryCredentials({ adminKey: 'axly_adm_test' });
    renderApp({ route: '/login' });
    await user.type(screen.getByLabelText(/Admin API Key/i), 'axly_adm_test');
    // Force pass login before failing agents
    failAgents = false;
    await user.click(screen.getByRole('button', { name: /Authenticate Session/i }));
    await screen.findByRole('heading', { name: 'Overview' });

    failAgents = true;
    await user.click(screen.getByRole('link', { name: 'Agents' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/Database query failed/i);
    expect(screen.getByRole('alert')).toHaveTextContent(/cid-err-99/i);

    failAgents = false;
    await user.click(screen.getByRole('button', { name: /Retry/i }));
    expect(await screen.findByText(/No agents registered yet/i)).toBeInTheDocument();
  });
});
