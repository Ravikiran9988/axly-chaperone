export function BrandLogo({ compact = false }) {
  return (
    <div className="flex items-center gap-2.5">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-sky-500/30 bg-sky-500/10 text-sky-500 dark:text-sky-400">
        <svg
          viewBox="0 0 24 24"
          className="h-4.5 w-4.5"
          width="18"
          height="18"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
      </div>
      {!compact && (
        <div className="min-w-0 leading-tight">
          <div className="flex items-center gap-1.5">
            <span className="text-sm font-semibold tracking-tight text-slate-900 dark:text-slate-100">
              AXLY Chaperone
            </span>
          </div>
          <p className="text-[11px] font-medium text-slate-500 dark:text-slate-400">
            Security Gateway
          </p>
        </div>
      )}
    </div>
  );
}
