import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { installMockApiAdapter, paginated, renderApp, signInAsAdmin } from './testUtils';

describe('Approval workflow', () => {
  it('inspects redacted payload, requires confirmation, approves & executes, and displays verification', async () => {
    const user = userEvent.setup();
    const approvalRecord = {
      id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      correlation_id: 'corr-approval-001',
      agent_id: 'ag-11111111-1111-1111-1111-111111111111',
      tool_name: 'email_tool',
      action: 'send',
      resource: 'finance@company.com',
      sanitized_arguments: {
        to: 'finance@company.com',
        subject: 'Invoice Summary',
        body: 'Invoice INV-2026-001 total 45000 INR',
        api_key: 'should-be-redacted-by-ui',
      },
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
      if (url === '/api/v1/agents') {
        return {
          data: paginated([
            {
              id: 'ag-11111111-1111-1111-1111-111111111111',
              name: 'invoice-summary-agent',
              key_prefix: 'axly_ag_1234...',
              status: 'active',
              created_at: '2026-11-27T09:00:00Z',
              updated_at: '2026-11-27T09:00:00Z',
            },
          ]),
        };
      }
      if (url === '/api/v1/tools') {
        return {
          data: paginated([
            {
              id: 't-email',
              name: 'email_tool',
              description: 'Mock email',
              category: 'communication',
              risk_level: 'high',
              enabled: true,
              created_at: '2026-11-27T09:00:00Z',
              updated_at: '2026-11-27T09:00:00Z',
            },
          ]),
        };
      }
      if (url === '/api/v1/approvals') return { data: paginated([approvalRecord]) };
      if (url === `/api/v1/approvals/${approvalRecord.id}` && method === 'GET') {
        return { data: approvalRecord };
      }
      if (url === `/api/v1/approvals/${approvalRecord.id}/approve` && method === 'POST') {
        approvalRecord.status = 'executed';
        approvalRecord.reviewer_id = 'admin:abc123';
        approvalRecord.reviewer_comment = body.comment;
        approvalRecord.reviewed_at = '2026-11-27T10:02:00Z';
        return {
          data: {
            approval: approvalRecord,
            execution_status: 'EXECUTED',
            output: { email_id: 'em-1', status: 'sent' },
            verification: {
              verification_id: 'ver-1',
              status: 'VERIFIED',
              method: 'mock_email_db_query',
              message: 'Mock email recipient, subject, and delivery status independently verified.',
            },
          },
        };
      }
      if (url === '/api/v1/audit-events') {
        return {
          data: paginated([
            {
              id: 'ev-1',
              event_type: 'policy_evaluation',
              correlation_id: 'corr-approval-001',
              agent_id: approvalRecord.agent_id,
              tool_name: 'email_tool',
              action: 'send',
              resource: 'finance@company.com',
              decision: 'require_approval',
              reason: "Human approval required by policy 'approve-internal-email' (priority 100)",
              execution_status: 'pending_approval',
              verification_status: 'verified',
              created_at: '2026-11-27T10:00:00Z',
            },
          ]),
        };
      }
      return undefined;
    });

    renderApp({ route: '/login' });
    await signInAsAdmin(user);

    const mainNav = screen.getByRole('navigation', { name: 'Main navigation' });
    await user.click(within(mainNav).getByRole('link', { name: /Approvals/i }));
    await user.click(await screen.findByRole('button', { name: /Review/i }));

    expect(await screen.findByText(/Immutable Request Payload/i)).toBeInTheDocument();
    expect(screen.queryByText('should-be-redacted-by-ui')).not.toBeInTheDocument();
    expect(screen.getByText(/\[REDACTED\]/)).toBeInTheDocument();

    await user.type(screen.getByLabelText(/Reviewer Comment/i), 'Approved safe summary');
    await user.click(screen.getByRole('button', { name: /Approve & Execute Now/i }));

    // Confirmation dialog appears
    expect(await screen.findByText(/Confirm Approval & Immediate Execution/i)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /^Approve & Execute$/i }));

    await waitFor(() => {
      expect(screen.getByText(/Mock email recipient, subject, and delivery status independently verified/i)).toBeInTheDocument();
    });
  });
});
