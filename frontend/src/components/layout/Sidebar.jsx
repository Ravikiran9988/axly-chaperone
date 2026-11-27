import { useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import {
  Activity,
  Bot,
  CheckSquare,
  FileText,
  LayoutDashboard,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Wrench,
  X,
} from 'lucide-react';
import { BrandLogo } from './BrandLogo';
import { cn } from '../../utils/cn';

const NAV_ITEMS = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/agents', label: 'Agents', icon: Bot },
  { to: '/tools', label: 'Tools', icon: Wrench },
  { to: '/policies', label: 'Policies', icon: ShieldCheck },
  { to: '/approvals', label: 'Approvals', icon: CheckSquare, showBadge: true },
  { to: '/security-events', label: 'Security Events', icon: ShieldAlert },
  { to: '/audit-logs', label: 'Audit Logs', icon: FileText },
  { to: '/settings', label: 'Settings', icon: Settings },
];

function SidebarContent({ pendingCount, onNavigate, healthState }) {
  return (
    <div className="flex h-full flex-col justify-between">
      <div>
        <div className="flex h-16 items-center justify-between border-b border-slate-200 px-5 dark:border-slate-800/80">
          <BrandLogo />
          {onNavigate && (
            <button
              type="button"
              onClick={onNavigate}
              aria-label="Close navigation menu"
              className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-obsidian-800 dark:hover:text-slate-200 lg:hidden"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>

        <nav className="space-y-1 px-3 py-4" aria-label="Main navigation">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                onClick={onNavigate}
                className={({ isActive }) =>
                  cn(
                    'group flex items-center justify-between rounded-md px-3 py-2 text-xs font-medium transition-colors',
                    isActive
                      ? 'bg-sky-50 text-sky-700 dark:bg-sky-500/10 dark:text-sky-300'
                      : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-obsidian-850 dark:hover:text-slate-100'
                  )
                }
              >
                <span className="flex items-center gap-2.5">
                  <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span>{item.label}</span>
                </span>
                {item.showBadge && pendingCount > 0 && (
                  <span className="inline-flex min-w-[1.25rem] items-center justify-center rounded-full bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-semibold tabular-nums text-amber-600 dark:text-amber-300">
                    {pendingCount}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      <div className="border-t border-slate-200 px-4 py-4 dark:border-slate-800/80">
        <div className="flex items-center gap-2 text-[11px] text-slate-500 dark:text-slate-400">
          <Activity
            className={cn(
              'h-3.5 w-3.5 shrink-0',
              healthState === 'healthy'
                ? 'text-emerald-500'
                : healthState === 'degraded'
                  ? 'text-amber-500'
                  : 'text-rose-500'
            )}
            aria-hidden="true"
          />
          <span className="truncate">
            {healthState === 'healthy'
              ? 'Gateway Operational'
              : healthState === 'degraded'
                ? 'Database Degraded'
                : 'Gateway Offline'}
          </span>
        </div>
        <p className="mt-1.5 text-[11px] font-medium tracking-wide text-slate-400 dark:text-slate-500">
          Safe autonomy. Human control.
        </p>
      </div>
    </div>
  );
}

export function Sidebar({ mobileOpen, onCloseMobile, pendingCount = 0, healthState = 'healthy' }) {
  useEffect(() => {
    if (!mobileOpen) return undefined;
    const onKeyDown = (e) => {
      if (e.key === 'Escape') onCloseMobile();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [mobileOpen, onCloseMobile]);

  return (
    <>
      {/* Desktop sidebar */}
      <aside className="hidden w-64 shrink-0 border-r border-slate-200 bg-white dark:border-slate-800/80 dark:bg-obsidian-900 lg:block">
        <SidebarContent pendingCount={pendingCount} healthState={healthState} />
      </aside>

      {/* Mobile slide-over sidebar */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 flex lg:hidden" role="dialog" aria-modal="true" aria-label="Mobile navigation">
          <div className="fixed inset-0 bg-slate-950/75" onClick={onCloseMobile} aria-hidden="true" />
          <aside className="relative z-10 w-64 max-w-[80vw] border-r border-slate-200 bg-white dark:border-slate-800 dark:bg-obsidian-900">
            <SidebarContent
              pendingCount={pendingCount}
              onNavigate={onCloseMobile}
              healthState={healthState}
            />
          </aside>
        </div>
      )}
    </>
  );
}
