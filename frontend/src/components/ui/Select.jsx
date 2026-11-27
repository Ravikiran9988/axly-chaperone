import { forwardRef, useId } from 'react';
import { cn } from '../../utils/cn';

export const Select = forwardRef(function Select(
  { label, error, hint, className, id, children, ...props },
  ref
) {
  const generatedId = useId();
  const selectId = id || generatedId;

  return (
    <div className="space-y-1.5">
      {label && (
        <label
          htmlFor={selectId}
          className="block text-xs font-medium text-slate-700 dark:text-slate-300"
        >
          {label}
        </label>
      )}
      <select
        ref={ref}
        id={selectId}
        className={cn(
          'block w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 disabled:cursor-not-allowed disabled:opacity-60 dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100',
          error && 'border-rose-500 focus:border-rose-500 focus:ring-rose-500',
          className
        )}
        aria-invalid={Boolean(error)}
        {...props}
      >
        {children}
      </select>
      {error ? (
        <p className="text-xs text-rose-600 dark:text-rose-400" role="alert">
          {error}
        </p>
      ) : (
        hint && <p className="text-xs text-slate-500 dark:text-slate-400">{hint}</p>
      )}
    </div>
  );
});
