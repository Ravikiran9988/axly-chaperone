import { describe, expect, it } from 'vitest';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { installMockApiAdapter, paginated, renderApp, signInAsAdmin } from './testUtils';

describe('Audit logs and correlation execution timeline', () => {
  it('renders audit log entries and opens real chronological timeline without inventing stages', async () => {
    const user = userEvent.setup();
    const events = [
      {
        id: 'ev-1',
        event_type: 'policy_evaluation',
        correlation_id: 'demo-finance-email-004',
        agent_id: 'ag-1',
        tool_name: 'email_tool',
        action: 'send',
        resource: 'finance@company.com',
        decision: 'require_approval',
        reason: "Human approval required by policy 'demo-require-approval-company-email'",
        policy_id: 'pol-1',
        policy_version: 1,
        policy_metadata: null,
        approval_id: 'ap-1',
        reviewer_id: null,
        reviewed_at: null,
        verification_outcome: null,
        execution_metadata: null,
        execution_status: 'pending_approval',
        verification_status: 'verified',
        created_at: '2026-11-27T10:00:00Z',
      },
      {
        id: 'ev-2',
        event_type: 'verification_completed',
        correlation_id: 'demo-finance-email-004',
        agent_id: 'ag-1',
        tool_name: 'email_tool',
        action: 'send',
        resource: 'finance@company.com',
        decision: 'allow',
        reason: 'Mock email recipient, subject, and delivery status independently verified.',
        policy_id: 'pol-1',
        policy_version: 1,
        policy_metadata: { verification_method: 'mock_email_db_query' },
        approval_id: 'ap-1',
        reviewer_id: 'admin:abc123',
        reviewed_at: '2026-11-27T10:01:00Z',
        verification_outcome: 'verified',
        execution_metadata: { verification_id: 'v-1' },
        execution_status: 'executed',
        verification_status: 'verified',
        created_at: '2026-11-27T10:01:05Z',
      },
    ];

    installMockApiAdapter(({ url, params }) => {
      if (url === '/health') return { data: { status: 'ok', service: 'AXLY Chaperone', version: '0.1.0' } };
      if (url === '/ready') return { data: { status: 'ready', service: 'AXLY Chaperone', database: 'connected' } };
      if (url === '/api/v1/audit-events') {
        if (params.correlation_id === 'demo-finance-email-004') {
          return { data: paginated(events) };
        }
        return { data: paginated(events) };
      }
      return undefined;
    });

    renderApp({ route: '/login' });
    await signInAsAdmin(user);

    await user.click(screen.getByRole('link', { name: 'Audit Logs' }));
    const cidButtons = await screen.findAllByRole('button', { name: /demo-fin/i });
    await user.click(cidButtons[0]);

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/Chronological Execution Lifecycle/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/1\. Policy Decision/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/2\. Independent Verification/i)).toBeInTheDocument();
    // Should NOT invent missing Authentication Gate or Execution Started stages
    expect(within(dialog).queryByText(/Authentication Gate/i)).not.toBeInTheDocument();
  });
});
