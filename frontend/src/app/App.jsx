import { BrowserRouter } from 'react-router-dom';
import { ErrorBoundary } from '../components/feedback/ErrorBoundary';
import { AppProviders } from './providers';
import { AppRouter } from './router';

export function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <AppProviders>
          <AppRouter />
        </AppProviders>
      </BrowserRouter>
    </ErrorBoundary>
  );
}

export default App;
