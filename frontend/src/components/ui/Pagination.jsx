import { ChevronLeft, ChevronRight } from 'lucide-react';
import { Button } from './Button';

export function Pagination({ page, totalPages, total, pageSize, onPageChange }) {
  if (!total || total <= 0) return null;
  const effectiveTotalPages = Math.max(1, totalPages || Math.ceil(total / pageSize));
  const start = (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);

  return (
    <div className="flex flex-col items-center justify-between gap-3 border-t border-slate-200 px-5 py-3 text-xs text-slate-500 dark:border-slate-800/80 dark:text-slate-400 sm:flex-row">
      <div className="tabular-nums">
        Showing <span className="font-medium text-slate-900 dark:text-slate-200">{start}</span>–
        <span className="font-medium text-slate-900 dark:text-slate-200">{end}</span> of{' '}
        <span className="font-medium text-slate-900 dark:text-slate-200">{total}</span>
      </div>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="xs"
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1}
          aria-label="Previous page"
        >
          <ChevronLeft className="h-3.5 w-3.5" />
          Prev
        </Button>
        <span className="px-2 tabular-nums">
          Page {page} of {effectiveTotalPages}
        </span>
        <Button
          variant="outline"
          size="xs"
          onClick={() => onPageChange(page + 1)}
          disabled={page >= effectiveTotalPages}
          aria-label="Next page"
        >
          Next
          <ChevronRight className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}
