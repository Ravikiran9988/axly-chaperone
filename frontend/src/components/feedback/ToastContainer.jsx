import { AlertTriangle, CheckCircle2, Info, X, XCircle } from 'lucide-react';
import { useToast } from '../../context/ToastContext';
import { cn } from '../../utils/cn';

const VARIANT_STYLES = {
  success: {
    border: 'border-emerald-300 dark:border-emerald-500/40',
    icon: CheckCircle2,
    iconColor: 'text-emerald-600 dark:text-emerald-400',
  },
  error: {
    border: 'border-rose-300 dark:border-rose-500/40',
    icon: XCircle,
    iconColor: 'text-rose-600 dark:text-rose-400',
  },
  warning: {
    border: 'border-amber-300 dark:border-amber-500/40',
    icon: AlertTriangle,
    iconColor: 'text-amber-600 dark:text-amber-400',
  },
  info: {
    border: 'border-sky-300 dark:border-sky-500/40',
    icon: Info,
    iconColor: 'text-sky-600 dark:text-sky-400',
  },
};

export function ToastContainer() {
  const { toasts, dismissToast } = useToast();

  if (!toasts.length) return null;

  return (
    <div
      aria-live="polite"
      aria-label="Notifications"
      className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-full max-w-sm flex-col gap-2 px-4 sm:px-0"
    >
      {toasts.map((toast) => {
        const cfg = VARIANT_STYLES[toast.variant] || VARIANT_STYLES.info;
        const Icon = cfg.icon;
        return (
          <div
            key={toast.id}
            role="status"
            className={cn(
              'pointer-events-auto flex items-start gap-3 rounded-lg border bg-white p-3.5 shadow-lg dark:bg-obsidian-900',
              cfg.border
            )}
          >
            <Icon className={cn('mt-0.5 h-4 w-4 shrink-0', cfg.iconColor)} aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <p className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                {toast.title}
              </p>
              {toast.description && (
                <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                  {toast.description}
                </p>
              )}
            </div>
            <button
              type="button"
              onClick={() => dismissToast(toast.id)}
              aria-label="Dismiss notification"
              className="rounded p-0.5 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
