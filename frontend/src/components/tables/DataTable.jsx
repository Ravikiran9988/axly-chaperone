import { cn } from '../../utils/cn';
import { TableSkeleton } from '../ui/Skeleton';
import { EmptyState } from '../ui/EmptyState';
import { ErrorState } from '../ui/ErrorState';

export function DataTable({
  columns,
  rows,
  rowKey = 'id',
  isLoading = false,
  error = null,
  onRetry,
  emptyTitle = 'No records found',
  emptyDescription = 'No items match the current filters.',
  emptyIcon,
  emptyAction,
  onRowClick,
  rowClassName,
}) {
  if (isLoading) {
    return <TableSkeleton rows={6} cols={Math.min(columns.length, 6)} />;
  }

  if (error) {
    return (
      <div className="p-4">
        <ErrorState error={error} onRetry={onRetry} />
      </div>
    );
  }

  if (!rows || rows.length === 0) {
    return (
      <EmptyState
        icon={emptyIcon}
        title={emptyTitle}
        description={emptyDescription}
        action={emptyAction}
      />
    );
  }

  return (
    <div className="w-full overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">
        <thead>
          <tr className="border-b border-slate-200 bg-slate-50/80 dark:border-slate-800/80 dark:bg-obsidian-850">
            {columns.map((col) => (
              <th
                key={col.key}
                scope="col"
                className={cn(
                  'whitespace-nowrap px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400',
                  col.headerClassName
                )}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-200 dark:divide-slate-800/80">
          {rows.map((row, idx) => {
            const key = typeof rowKey === 'function' ? rowKey(row, idx) : row[rowKey];
            const extraRowClass = typeof rowClassName === 'function' ? rowClassName(row) : rowClassName;
            return (
              <tr
                key={key}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                className={cn(
                  'transition-colors hover:bg-slate-50/90 dark:hover:bg-obsidian-850/70',
                  onRowClick && 'cursor-pointer',
                  extraRowClass
                )}
              >
                {columns.map((col) => (
                  <td
                    key={col.key}
                    className={cn(
                      'px-4 py-3 text-xs text-slate-700 dark:text-slate-300',
                      col.cellClassName
                    )}
                  >
                    {col.render ? col.render(row) : row[col.key]}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
