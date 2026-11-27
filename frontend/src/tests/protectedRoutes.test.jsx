import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { installMockApiAdapter, paginated, renderApp } from './testUtils';

describe('Protected routes', () => {
  it('redirects unauthenticated users from protected dashboard routes to /login', async () => {
    installMockApiAdapter(({ url }) => {
      if (url === '/health') return { data: { status: 'ok', service: 'AXLY Chaperone', version: '0.1.0' } };
      if (url === '/ready') return { data: { status: 'ready', service: 'AXLY Chaperone', database: 'connected' } };
      return undefined;
    });

    renderApp({ route: '/policies' });
    expect(await screen.findByRole('heading', { name: /Administrator Sign In/i })).toBeInTheDocument();
  });
});
