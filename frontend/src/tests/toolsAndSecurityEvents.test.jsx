import { describe, expect, it } from 'vitest';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { installMockApiAdapter, paginated, renderApp, signInAsAdmin } from './testUtils';

describe('Tools execution distinction, Security Events, and Settings health', () => {
  it('distinguishes executable adapter tools from evaluation-only tools and renders security events and settings', async () => {
    const user = userEvent.setup();
    const tools = [
      {
        id: 't-1',
        name: 'file_tool',
        description: 'Sandboxed filesystem tool',
        category: 'filesystem',
        risk_level: 'medium',
        enabled: true,
        created_at: '2026-11-27T10:00:00Z',
        updated_at: '2026-11-27T10:00:00Z',
      },
      {
        id: 't-2',
        name: 'custom_eval_tool',
        description: 'Custom policy-only metadata tool',
        category: 'custom',
        risk_level: 'low',
        enabled: true,
        created_at: '2026-11-27T10:00:00Z',
        updated_at: '2026-11-27T10:00:00Z',
      },
    ];

    const auditEvents = [
      {
        id: 'sec-1',
        event_type: 'policy_evaluation',
        correlation_id: 'corr-denied-private-001',
        agent_id: null,
        tool_name: 'file_tool',
        action: 'read',
        resource: 'private/secrets.txt',
        decision: 'deny',
        reason: "Denied by explicit policy 'demo-deny-private-files'",
        execution_status: 'blocked',
        verification_status: 'verified',
        created_at: '2026-11-27T10:05:00Z',
      },
    ];

    installMockApiAdapter(({ url }) => {
      if (url === '/health') return { data: { status: 'ok', service: 'AXLY Chaperone', version: '0.1.0' } };
      if (url === '/ready') return { data: { status: 'ready', service: 'AXLY Chaperone', database: 'connected' } };
      if (url === '/api/v1/tools') return { data: paginated(tools) };
      if (url === '/api/v1/audit-events') return { data: paginated(auditEvents) };
      return undefined;
    });

    renderApp({ route: '/login' });
    await signInAsAdmin(user);

    const mainNav = screen.getByRole('navigation', { name: 'Main navigation' });
    await user.click(within(mainNav).getByRole('link', { name: 'Tools' }));

    expect(await screen.findByText('Executable Adapter')).toBeInTheDocument();
    expect(screen.getByText('Evaluation Only')).toBeInTheDocument();

    await user.click(within(mainNav).getByRole('link', { name: 'Security Events' }));
    expect(await screen.findByText('private/secrets.txt')).toBeInTheDocument();

    await user.click(within(mainNav).getByRole('link', { name: 'Settings' }));
    expect(await screen.findByText(/STDIO \/ NOT EXPOSED OVER HTTP/i)).toBeInTheDocument();
    expect(screen.getByText('v0.1.0')).toBeInTheDocument();
  });
});
