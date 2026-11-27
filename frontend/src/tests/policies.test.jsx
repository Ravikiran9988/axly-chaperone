import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { installMockApiAdapter, paginated, renderApp } from './testUtils';

describe('Policy creation and broad-permission warnings', () => {
  it('validates policy scope, warns on broad ALLOW rules, and creates policy via API', async () => {
    const user = userEvent.setup();
    const policies = [];
    const tools = [
      {
        id: 't-1',
        name: 'file_tool',
        description: 'Sandboxed file adapter',
        category: 'filesystem',
        risk_level: 'medium',
        enabled: true,
        created_at: '2026-11-27T10:00:00Z',
        updated_at: '2026-11-27T10:00:00Z',
      },
    ];

    installMockApiAdapter(({ method, url, body }) => {
      if (url === '/health') return { data: { status: 'ok', service: 'AXLY Chaperone', version: '0.1.0' } };
      if (url === '/ready') return { data: { status: 'ready', service: 'AXLY Chaperone', database: 'connected' } };
      if (url === '/api/v1/tools') return { data: paginated(tools) };
      if (url === '/api/v1/agents') return { data: paginated([]) };
      if (method === 'GET' && url === '/api/v1/policies') return { data: paginated(policies) };
      if (method === 'POST' && url === '/api/v1/policies') {
        const created = {
          id: 'p-1',
          version: 1,
          created_at: '2026-11-27T10:00:00Z',
          updated_at: '2026-11-27T10:00:00Z',
          ...body,
        };
        policies.push(created);
        return { status: 201, data: created };
      }
      return { data: paginated([]) };
    });

    renderApp({ route: '/login' });
    await user.type(screen.getByLabelText(/Admin API Key/i), 'axly_adm_valid');
    await user.click(screen.getByRole('button', { name: /Authenticate Session/i }));
    await screen.findByRole('heading', { name: 'Overview' });

    await user.click(screen.getByRole('link', { name: 'Policies' }));
    const createButtons = await screen.findAllByRole('button', { name: /Create Policy/i });
    await user.click(createButtons[0]);

    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText(/Policy Name/i), 'allow-docs-read');
    await user.selectOptions(within(dialog).getByLabelText(/Registered Tool/i), 'file_tool');
    await user.type(within(dialog).getByLabelText(/^Action$/i), '*');
    await user.type(within(dialog).getByLabelText(/Resource Scope/i), '*');
    await user.selectOptions(within(dialog).getByLabelText(/^Decision$/i), 'allow');

    expect(await within(dialog).findByText(/Broad Permission Warning/i)).toBeInTheDocument();

    // Verify invalid traversal scope is rejected client-side
    await user.clear(within(dialog).getByLabelText(/Resource Scope/i));
    await user.type(within(dialog).getByLabelText(/Resource Scope/i), '../secrets/*');
    await user.click(within(dialog).getByRole('button', { name: 'Create Policy' }));
    expect(await within(dialog).findByText(/Path traversal/i)).toBeInTheDocument();

    await user.clear(within(dialog).getByLabelText(/Resource Scope/i));
    await user.type(within(dialog).getByLabelText(/Resource Scope/i), 'documents/*');
    await user.click(within(dialog).getByRole('button', { name: 'Create Policy' }));

    await waitFor(() => {
      expect(screen.getByText('allow-docs-read')).toBeInTheDocument();
    });
  });
});
