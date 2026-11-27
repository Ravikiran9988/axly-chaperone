import '@testing-library/jest-dom/vitest';
import { afterEach, vi } from 'vitest';
import { cleanup, configure } from '@testing-library/react';
import { clearMemoryCredentials, apiClient } from '../services/api';

configure({ asyncUtilTimeout: 5000 });

const originalAdapter = apiClient.defaults.adapter;

class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}

globalThis.ResizeObserver = ResizeObserverMock;

if (!globalThis.navigator?.clipboard) {
  Object.defineProperty(globalThis.navigator, 'clipboard', {
    value: {
      writeText: vi.fn().mockResolvedValue(undefined),
    },
    configurable: true,
  });
}

afterEach(() => {
  cleanup();
  clearMemoryCredentials();
  apiClient.defaults.adapter = originalAdapter;
  window.localStorage.clear();
  vi.restoreAllMocks();
});
