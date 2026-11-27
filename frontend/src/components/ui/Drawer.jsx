import { useEffect } from 'react';
import { X } from 'lucide-react';
import { cn } from '../../utils/cn';

const WIDTHS = {
  md: 'max-w-lg',
  lg: 'max-w-2xl',
  xl: 'max-w-3xl',
};

export function Drawer({ open, onClose, title, subtitle, width = 'lg', children, footer }) {
  useEffect(() => {
    if (!open) return undefined;
    const onKeyDown = (e) => {
      if (e.key === 'Escape') onClose?.();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
      <div className="fixed inset-0 bg-slate-950/70" onClick={onClose} aria-hidden="true" />
      <div
        className={cn(
          'relative z-10 flex h-full w-full flex-col border-l border-slate-200 bg-white shadow-2xl dark:border-slate-800 dark:bg-obsidian-900',
          WIDTHS[width] || WIDTHS.lg
        )}
      >
        <div className="flex items-start justify-between gap-4 border-b border-slate-200 px-6 py-4 dark:border-slate-800/80">
          <div className="min-w-0">
            <h3 id="drawer-title" className="truncate text-base font-semibold text-slate-900 dark:text-slate-100">
              {title}
            </h3>
            {subtitle && (
              <p className="mt-0.5 truncate text-xs text-slate-500 dark:text-slate-400">{subtitle}</p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close panel"
            className="rounded p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-obsidian-800 dark:hover:text-slate-200"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>
        {footer && (
          <div className="flex flex-wrap items-center justify-end gap-2 border-t border-slate-200 px-6 py-4 dark:border-slate-800/80">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
