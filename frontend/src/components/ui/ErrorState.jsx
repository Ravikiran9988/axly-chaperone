import { AlertCircle, RefreshCw } from 'lucide-react';
import { Button } from './Button';

export function ErrorState({
  title = 'Failed to load data',
  error,
  onRetry,
}) {
  const message =
    error?.message || 'An unexpected error occurred while querying the Chaperone API.';

  return (
    <div
      role="alert"
      className="flex flex-col items-center justify-center rounded-lg border border-rose-200 bg-rose-50/50 px-6 py-10 text-center dark:border-rose-500/30 dark:bg-rose-500/5"
    >
      <div className="flex h-10 w-10 items-center justify-center rounded-full bg-rose-100 text-rose-600 dark:bg-rose-500/15 dark:text-rose-400">
        <AlertCircle className="h-5 w-5" aria-hidden="true" />
      </div>
      <h3 className="mt-3 text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</h3>
      <p className="mt-1 max-w-lg text-xs text-slate-600 dark:text-slate-400">{message}</p>
      {error?.code && (
        <p className="mt-1 font-mono text-[11px] text-rose-600 dark:text-rose-400">
          Code: {error.code}
          {error.correlationId ? ` • Correlation: ${error.correlationId}` : ''}
        </p>
      )}
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry} className="mt-4">
          <RefreshCw className="h-3.5 w-3.5" />
          Retry
        </Button>
      )}
    </div>
  );
}
