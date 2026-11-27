import { cn } from '../../utils/cn';

export function Card({ className, children, ...props }) {
  return (
    <div
      className={cn(
        'rounded-lg border border-slate-200 bg-white dark:border-slate-800/80 dark:bg-obsidian-900',
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardHeader({ className, children, ...props }) {
  return (
    <div
      className={cn(
        'flex flex-col gap-1 border-b border-slate-200 px-5 py-4 dark:border-slate-800/80 sm:flex-row sm:items-center sm:justify-between',
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardTitle({ className, children, ...props }) {
  return (
    <h2
      className={cn('text-sm font-semibold tracking-tight text-slate-900 dark:text-slate-100', className)}
      {...props}
    >
      {children}
    </h2>
  );
}

export function CardDescription({ className, children, ...props }) {
  return (
    <p className={cn('text-xs text-slate-500 dark:text-slate-400', className)} {...props}>
      {children}
    </p>
  );
}

export function CardContent({ className, children, ...props }) {
  return (
    <div className={cn('p-5', className)} {...props}>
      {children}
    </div>
  );
}
