import { forwardRef } from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '../../utils/cn';

const VARIANTS = {
  primary:
    'bg-sky-600 text-white hover:bg-sky-500 active:bg-sky-700 dark:bg-sky-500 dark:text-slate-950 dark:hover:bg-sky-400 shadow-sm border border-transparent',
  secondary:
    'bg-slate-100 text-slate-900 hover:bg-slate-200 dark:bg-obsidian-800 dark:text-slate-100 dark:hover:bg-obsidian-700 border border-slate-200 dark:border-slate-700/80',
  outline:
    'bg-transparent text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-obsidian-800 border border-slate-300 dark:border-slate-700',
  danger:
    'bg-rose-600 text-white hover:bg-rose-500 active:bg-rose-700 dark:bg-rose-600 dark:hover:bg-rose-500 border border-transparent',
  success:
    'bg-emerald-600 text-white hover:bg-emerald-500 active:bg-emerald-700 border border-transparent',
  ghost:
    'bg-transparent text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-obsidian-800 dark:hover:text-slate-100 border border-transparent',
};

const SIZES = {
  xs: 'h-7 px-2.5 text-xs gap-1.5',
  sm: 'h-8 px-3 text-xs gap-1.5',
  md: 'h-9 px-4 text-sm gap-2',
  lg: 'h-10 px-5 text-sm gap-2',
};

export const Button = forwardRef(function Button(
  {
    variant = 'primary',
    size = 'md',
    isLoading = false,
    disabled = false,
    type = 'button',
    className,
    children,
    ...props
  },
  ref
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || isLoading}
      className={cn(
        'inline-flex items-center justify-center rounded-md font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 focus-visible:ring-offset-2 focus-visible:ring-offset-white dark:focus-visible:ring-offset-obsidian-950 disabled:cursor-not-allowed disabled:opacity-50',
        VARIANTS[variant] || VARIANTS.primary,
        SIZES[size] || SIZES.md,
        className
      )}
      {...props}
    >
      {isLoading && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />}
      {children}
    </button>
  );
});
