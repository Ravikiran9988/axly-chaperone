import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Bell,
  ChevronRight,
  Clock,
  LogOut,
  Menu,
  Moon,
  Shield,
  Sun,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { formatRelativeTime } from '../../utils/formatters';
import { cn } from '../../utils/cn';

export function Topbar({
  title,
  breadcrumbs = [],
  onOpenMobileMenu,
  healthQuery,
  readinessQuery,
  pendingApprovals = [],
  pendingCount = 0,
}) {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [notifOpen, setNotifOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const notifRef = useRef(null);
  const profileRef = useRef(null);

  useEffect(() => {
    const onDocClick = (e) => {
      if (notifRef.current && !notifRef.current.contains(e.target)) setNotifOpen(false);
      if (profileRef.current && !profileRef.current.contains(e.target)) setProfileOpen(false);
    };
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, []);

  const apiConnected = healthQuery?.isSuccess && healthQuery?.data?.status === 'ok';
  const dbReady = readinessQuery?.isSuccess && readinessQuery?.data?.database === 'connected';
  const connectionLabel = !apiConnected
    ? 'API Offline'
    : dbReady
      ? `Connected${healthQuery?.data?.latencyMs != null ? ` (${healthQuery.data.latencyMs}ms)` : ''}`
      : 'DB Degraded';

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center justify-between gap-4 border-b border-slate-200 bg-white/95 px-4 backdrop-blur-sm dark:border-slate-800/80 dark:bg-obsidian-900/95 sm:px-6">
      <div className="flex min-w-0 items-center gap-3">
        <button
          type="button"
          onClick={onOpenMobileMenu}
          aria-label="Open navigation menu"
          className="rounded-md p-2 text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-obsidian-800 dark:hover:text-slate-100 lg:hidden"
        >
          <Menu className="h-5 w-5" />
        </button>

        <div className="min-w-0">
          {breadcrumbs.length > 0 && (
            <nav aria-label="Breadcrumb" className="hidden items-center gap-1 text-[11px] text-slate-500 dark:text-slate-400 sm:flex">
              {breadcrumbs.map((crumb, idx) => (
                <span key={crumb.label} className="flex items-center gap-1">
                  {idx > 0 && <ChevronRight className="h-3 w-3 text-slate-400" />}
                  {crumb.to ? (
                    <Link to={crumb.to} className="hover:text-slate-900 dark:hover:text-slate-200">
                      {crumb.label}
                    </Link>
                  ) : (
                    <span className="truncate text-slate-600 dark:text-slate-300">{crumb.label}</span>
                  )}
                </span>
              ))}
            </nav>
          )}
          <h1 className="truncate text-base font-semibold tracking-tight text-slate-900 dark:text-slate-100">
            {title}
          </h1>
        </div>
      </div>

      <div className="flex items-center gap-2 sm:gap-3">
        {/* Backend connection status */}
        <Link
          to="/settings"
          title="View backend health and readiness"
          className={cn(
            'hidden items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium sm:inline-flex',
            !apiConnected
              ? 'border-rose-300 bg-rose-50 text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300'
              : dbReady
                ? 'border-emerald-300 bg-emerald-50 text-emerald-700 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-300'
                : 'border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300'
          )}
        >
          {apiConnected ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
          <span className="tabular-nums">{connectionLabel}</span>
        </Link>

        {/* Pending Approvals Notification Indicator (real backend queue) */}
        <div className="relative" ref={notifRef}>
          <button
            type="button"
            onClick={() => setNotifOpen((prev) => !prev)}
            aria-label={`Pending approvals (${pendingCount})`}
            aria-expanded={notifOpen}
            className="relative rounded-md border border-slate-200 p-2 text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:border-slate-800 dark:text-slate-300 dark:hover:bg-obsidian-800 dark:hover:text-slate-100"
          >
            <Bell className="h-4 w-4" />
            {pendingCount > 0 && (
              <span className="absolute -right-1 -top-1 flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-amber-500 px-1 text-[10px] font-bold tabular-nums text-slate-950">
                {pendingCount > 99 ? '99+' : pendingCount}
              </span>
            )}
          </button>

          {notifOpen && (
            <div className="absolute right-0 mt-2 w-80 rounded-lg border border-slate-200 bg-white shadow-xl dark:border-slate-700/80 dark:bg-obsidian-900">
              <div className="flex items-center justify-between border-b border-slate-200 px-4 py-2.5 dark:border-slate-800">
                <span className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                  Pending Approvals ({pendingCount})
                </span>
                <Link
                  to="/approvals"
                  onClick={() => setNotifOpen(false)}
                  className="text-[11px] font-medium text-sky-600 hover:text-sky-500 dark:text-sky-400"
                >
                  Open queue
                </Link>
              </div>
              <div className="max-h-72 divide-y divide-slate-100 overflow-y-auto dark:divide-slate-800/80">
                {pendingApprovals.length === 0 ? (
                  <p className="px-4 py-6 text-center text-xs text-slate-500 dark:text-slate-400">
                    No pending human approvals.
                  </p>
                ) : (
                  pendingApprovals.map((item) => (
                    <Link
                      key={item.id}
                      to={`/approvals?highlight=${item.id}`}
                      onClick={() => setNotifOpen(false)}
                      className="block px-4 py-2.5 hover:bg-slate-50 dark:hover:bg-obsidian-850"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs font-medium text-slate-900 dark:text-slate-100">
                          {item.tool_name} · {item.action}
                        </span>
                        <span className="inline-flex items-center gap-1 text-[10px] text-amber-600 dark:text-amber-400">
                          <Clock className="h-3 w-3" />
                          {formatRelativeTime(item.requested_at)}
                        </span>
                      </div>
                      <p className="mt-0.5 truncate font-mono text-[11px] text-slate-500 dark:text-slate-400">
                        {item.resource}
                      </p>
                    </Link>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* Theme toggle */}
        <button
          type="button"
          onClick={toggleTheme}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          className="rounded-md border border-slate-200 p-2 text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:border-slate-800 dark:text-slate-300 dark:hover:bg-obsidian-800 dark:hover:text-slate-100"
        >
          {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>

        {/* User Profile / Logout */}
        <div className="relative" ref={profileRef}>
          <button
            type="button"
            onClick={() => setProfileOpen((prev) => !prev)}
            aria-expanded={profileOpen}
            className="flex items-center gap-2 rounded-md border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-800 dark:text-slate-200 dark:hover:bg-obsidian-800"
          >
            <Shield className="h-3.5 w-3.5 text-sky-500" aria-hidden="true" />
            <span className="hidden max-w-[110px] truncate sm:inline">
              {user?.actor || 'admin'}
            </span>
          </button>

          {profileOpen && (
            <div className="absolute right-0 mt-2 w-60 rounded-lg border border-slate-200 bg-white p-2 shadow-xl dark:border-slate-700/80 dark:bg-obsidian-900">
              <div className="border-b border-slate-100 px-2.5 py-2 dark:border-slate-800">
                <p className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                  {user?.actor || 'admin'}
                </p>
                <p className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
                  Scheme: <span className="font-mono">{user?.authScheme || 'x-admin-key'}</span>
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  setProfileOpen(false);
                  logout({ type: 'info', message: 'You have been signed out safely.' });
                }}
                className="mt-1 flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-xs font-medium text-rose-600 hover:bg-rose-50 dark:text-rose-400 dark:hover:bg-rose-500/10"
              >
                <LogOut className="h-3.5 w-3.5" />
                Sign Out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
