import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';
import { useHealthQuery, useReadinessQuery } from '../../hooks/useHealth';
import { usePendingApprovalsCount } from '../../hooks/useApprovals';

export function AppShell({ title, breadcrumbs = [], children }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const healthQuery = useHealthQuery();
  const readinessQuery = useReadinessQuery();
  const pendingSummary = usePendingApprovalsCount(true);

  const apiConnected = healthQuery.isSuccess && healthQuery.data?.status === 'ok';
  const dbReady = readinessQuery.isSuccess && readinessQuery.data?.database === 'connected';
  const healthState = !apiConnected ? 'offline' : dbReady ? 'healthy' : 'degraded';

  const pendingCount = pendingSummary.data?.total ?? 0;
  const pendingApprovals = pendingSummary.data?.items ?? [];

  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900 dark:bg-obsidian-950 dark:text-slate-100">
      <Sidebar
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
        pendingCount={pendingCount}
        healthState={healthState}
      />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar
          title={title}
          breadcrumbs={breadcrumbs}
          onOpenMobileMenu={() => setMobileOpen(true)}
          healthQuery={healthQuery}
          readinessQuery={readinessQuery}
          pendingApprovals={pendingApprovals}
          pendingCount={pendingCount}
        />
        <main className="flex-1 p-4 sm:p-6">
          <div className="mx-auto max-w-7xl space-y-6">{children || <Outlet />}</div>
        </main>
      </div>
    </div>
  );
}
