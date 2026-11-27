import { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '../context/AuthContext';
import { ThemeProvider } from '../context/ThemeContext';
import { ToastProvider } from '../context/ToastContext';
import { ToastContainer } from '../components/feedback/ToastContainer';

export function createAppQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: (failureCount, error) => {
          if (error?.status && [400, 401, 403, 404, 409, 422, 503].includes(error.status)) {
            return false;
          }
          return failureCount < 1;
        },
        refetchOnWindowFocus: false,
      },
    },
  });
}

export function AppProviders({ children, queryClient: externalClient }) {
  const [defaultClient] = useState(() => createAppQueryClient());
  const client = externalClient || defaultClient;

  return (
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <ToastProvider>
          <AuthProvider>
            {children}
            <ToastContainer />
          </AuthProvider>
        </ToastProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}
