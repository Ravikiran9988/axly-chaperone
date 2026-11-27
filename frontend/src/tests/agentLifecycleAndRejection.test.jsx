import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { installMockApiAdapter, paginated, renderApp, signInAsAdmin } from './testUtils';

describe('Agent lifecycle details and approval rejection flows', () => {
  it('views agent details, disables an agent with confirmation, and rejects a pending approval', async () => {
    const user = userEvent.setup();
    const agent = {
      id: 'ag-99999999-9999-9999-9999-999999999999',
      name: 'ops-worker-agent',
      description: 'Runs operational database checks',
      key_prefix: 'axly_ag_99998888...',
      status: 'active',
      created_at: '2026-11-27T09:00:00Z',
      updated_at: '2026-11-27T09:00:00Z',
    };
    const pendingApproval = {
      id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
      correlation_id: 'corr-reject-001',
      agent_id: agent.id,
      tool_name: 'email_tool',
      action: 'send',
      resource: 'external@company.com',
      sanitized_arguments: { to: 'external@company.com', subject: 'Test', body: 'Check' },
      status: 'pending',
      requested_at: '2026-11-27T10:00:00Z',
      expires_at: '2099-11-27T10:15:00Z',
      reviewed_at: null,
      reviewer_id: null,
      reviewer_comment: null,
      execution_result_reference: null,
    };

    installMockApiAdapter(({ method, url, body }) => {
      if (url === '/health') return { data: { status: 'ok', service: 'AXLY Chaperone', version: '0.1.0' } };
      if (url === '/ready') return { data: { status: 'ready', service: 'AXLY Chaperone', database: 'connected' } };
      if (url === '/api/v1/agents') return { data: paginated([agent]) };
      if (url === `/api/v1/agents/${agent.id}`) return { data: agent };
      if (url === `/api/v1/agents/${agent.id}/status` && method === 'PATCH') {
        agent.status = body.status;
        return { data: { ...agent } };
      }
      if (url === '/api/v1/approvals') return { data: paginated([pendingApproval]) };
      if (url === `/api/v1/approvals/${pendingApproval.id}`) return { data: pendingApproval };
      if (url === `/api/v1/approvals/${pendingApproval.id}/reject` && method === 'POST') {
        pendingApproval.status = 'rejected';
        pendingApproval.reviewer_comment = body.comment;
        return { data: { approval: pendingApproval, execution_status: 'REJECTED' } };
      }
      return undefined;
    });

    renderApp({ route: '/login' });
    await signInAsAdmin(user);

    const mainNav = screen.getByRole('navigation', { name: 'Main navigation' });
    await user.click(within(mainNav).getByRole('link', { name: 'Agents' }));

    await user.click(await screen.findByRole('link', { name: 'ops-worker-agent' }));
    expect(await screen.findByRole('heading', { name: 'Agent Details' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /Disable Agent/i }));
    const confirmModal = await screen.findByRole('dialog');
    await user.click(within(confirmModal).getByRole('button', { name: /Disable Agent/i }));

    await waitFor(() => {
      expect(agent.status).toBe('disabled');
    });

    await user.click(within(mainNav).getByRole('link', { name: /Approvals/i }));
    await user.click(await screen.findByRole('button', { name: /Review/i }));

    await user.type(screen.getByLabelText(/Reviewer Comment/i), 'Out of policy window');
    await user.click(screen.getByRole('button', { name: /Reject Request/i }));

    const rejectConfirm = await screen.findByRole('dialog', { name: /Confirm Rejection/i });
    await user.click(within(rejectConfirm).getByRole('button', { name: /Reject Request/i }));

    await waitFor(() => {
      expect(pendingApproval.status).toBe('rejected');
    });
  });
});
