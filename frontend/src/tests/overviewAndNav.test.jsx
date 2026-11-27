import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { installMockApiAdapter, paginated, renderApp, signInAsAdmin } from './testUtils';

describe('Dashboard empty states and responsive navigation', () => {
  it('renders honest zero metrics and chart empty states when backend has no records', async () => {
    const user = userEvent.setup();

    installMockApiAdapter(({ url }) => {
      if (url === '/health') return { data: { status: 'ok', service: 'AXLY Chaperone', version: '0.1.0' } };
      if (url === '/ready') return { data: { status: 'ready', service: 'AXLY Chaperone', database: 'connected' } };
      if (url.startsWith('/api/v1/auth/')) return undefined;
      return { data: paginated([]) };
    });

    renderApp({ route: '/login' });
    await signInAsAdmin(user);
    expect(await screen.findByText(/No policy decisions recorded yet/i)).toBeInTheDocument();
    expect(screen.getByText(/No tool usage recorded/i)).toBeInTheDocument();
    expect(screen.getByText(/Insufficient historical trend data/i)).toBeInTheDocument();
    expect(screen.getByText(/No approval requests yet/i)).toBeInTheDocument();
  });

  it('opens and closes mobile responsive navigation drawer', async () => {
    const user = userEvent.setup();

    installMockApiAdapter(({ url }) => {
      if (url === '/health') return { data: { status: 'ok', service: 'AXLY Chaperone', version: '0.1.0' } };
      if (url === '/ready') return { data: { status: 'ready', service: 'AXLY Chaperone', database: 'connected' } };
      if (url.startsWith('/api/v1/auth/')) return undefined;
      return { data: paginated([]) };
    });

    renderApp({ route: '/login' });
    await signInAsAdmin(user);

    await user.click(screen.getByRole('button', { name: /Open navigation menu/i }));
    expect(await screen.findByRole('dialog', { name: /Mobile navigation/i })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /Close navigation menu/i }));
    expect(screen.queryByRole('dialog', { name: /Mobile navigation/i })).not.toBeInTheDocument();
  });
});
