import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { installMockApiAdapter, paginated, renderApp } from './testUtils';

describe('Agent registration and one-time key security', () => {
  it('registers an agent, reveals API key once with warning, copies it, and never stores in localStorage', async () => {
    const user = userEvent.setup();
    const agents = [];

    installMockApiAdapter(({ method, url, body }) => {
      if (url === '/health') return { data: { status: 'ok', service: 'AXLY Chaperone', version: '0.1.0' } };
      if (url === '/ready') return { data: { status: 'ready', service: 'AXLY Chaperone', database: 'connected' } };
      if (method === 'GET' && url === '/api/v1/agents') {
        return { data: paginated(agents) };
      }
      if (method === 'POST' && url === '/api/v1/agents') {
        const created = {
          id: '11111111-1111-1111-1111-111111111111',
          name: body.name,
          description: body.description,
          key_prefix: 'axly_ag_12345678...',
          status: 'active',
          created_at: '2026-11-27T10:00:00Z',
          updated_at: '2026-11-27T10:00:00Z',
        };
        agents.push(created);
        return {
          status: 201,
          data: { ...created, api_key: 'axly_ag_1234567890abcdef_supersecretkeyvalue123456' },
        };
      }
      return { data: paginated([]) };
    });

    renderApp({ route: '/login' });
    await user.type(screen.getByLabelText(/Admin API Key/i), 'axly_adm_valid');
    await user.click(screen.getByRole('button', { name: /Authenticate Session/i }));
    await screen.findByRole('heading', { name: 'Overview' });

    await user.click(screen.getByRole('link', { name: 'Agents' }));
    const openButtons = await screen.findAllByRole('button', { name: /Register Agent/i });
    await user.click(openButtons[0]);

    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText(/Agent Name/i), 'invoice-summary-agent');
    await user.type(within(dialog).getByLabelText(/Description/i), 'Handles invoice summaries');
    await user.click(within(dialog).getByRole('button', { name: 'Register Agent' }));

    // One-time key reveal modal appears
    expect(await screen.findByText(/Agent API Key Issued/i)).toBeInTheDocument();
    expect(screen.getByText(/cannot be retrieved again/i)).toBeInTheDocument();
    expect(screen.getByText('axly_ag_1234567890abcdef_supersecretkeyvalue123456')).toBeInTheDocument();

    // Confirm storage never holds raw agent key
    expect(JSON.stringify(window.localStorage)).not.toContain('axly_ag_1234567890abcdef');

    const doneBtn = screen.getByRole('button', { name: /I Have Saved This Key/i });
    expect(doneBtn).toBeDisabled();

    await user.click(screen.getByRole('checkbox'));
    expect(doneBtn).toBeEnabled();
    await user.click(doneBtn);

    await waitFor(() => {
      expect(screen.queryByText('axly_ag_1234567890abcdef_supersecretkeyvalue123456')).not.toBeInTheDocument();
    });
    expect(await screen.findByText('invoice-summary-agent')).toBeInTheDocument();
  });
});
