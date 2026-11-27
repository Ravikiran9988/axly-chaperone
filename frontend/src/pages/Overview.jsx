import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  Bot,
  CheckCircle2,
  Clock,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Wrench,
  XCircle,
} from 'lucide-react';
import { useDashboardMetrics } from '../hooks/useDashboardMetrics';
import { useHealthQuery, useReadinessQuery } from '../hooks/useHealth';
import { formatNumber, formatRelativeTime, formatShortTime, shortenId } from '../utils/formatters';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { EmptyState } from '../components/ui/EmptyState';
import { ErrorState } from '../components/ui/ErrorState';
import { CardGridSkeleton, Skeleton } from '../components/ui/Skeleton';
import { DecisionBreakdownChart } from '../components/charts/DecisionBreakdownChart';
import { ToolUsageChart } from '../components/charts/ToolUsageChart';
import { SecurityTrendsChart } from '../components/charts/SecurityTrendsChart';
import { ApprovalActivityChart } from '../components/charts/ApprovalActivityChart';

function MetricCard({ label, value, sublabel, icon: Icon, tone = 'neutral', to }) {
  const toneClasses = {
    neutral: 'text-slate-500 dark:text-slate-400',
    success: 'text-emerald-600 dark:text-emerald-400',
    danger: 'text-rose-600 dark:text-rose-400',
    warning: 'text-amber-600 dark:text-amber-400',
    info: 'text-sky-600 dark:text-sky-400',
  };

  const inner = (
    <Card className="h-full transition-colors hover:border-slate-300 dark:hover:border-slate-700">
      <CardContent className="p-4">
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
            {label}
          </span>
          <Icon className={`h-4 w-4 shrink-0 ${toneClasses[tone] || toneClasses.neutral}`} aria-hidden="true" />
        </div>
        <div className="mt-2 text-2xl font-semibold tracking-tight tabular-nums text-slate-900 dark:text-slate-100">
          {formatNumber(value)}
        </div>
        {sublabel && (
          <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">{sublabel}</p>
        )}
      </CardContent>
    </Card>
  );

  return to ? <Link to={to}>{inner}</Link> : inner;
}

export function Overview() {
  const [autoRefresh, setAutoRefresh] = useState(true);
  const dashboardQuery = useDashboardMetrics({
    refetchInterval: autoRefresh ? 30000 : false,
  });
  const healthQuery = useHealthQuery();
  const readinessQuery = useReadinessQuery();

  const data = dashboardQuery.data;
  const metrics = data?.metrics;
  const windowInfo = data?.auditWindowInfo;
  const lookups = data?.lookups;

  const chartScopeNote = windowInfo
    ? windowInfo.isCompleteHistory
      ? `Based on all ${windowInfo.totalEvents} recorded audit events`
      : `Based on latest ${windowInfo.fetchedEvents} of ${windowInfo.totalEvents} total audit events`
    : undefined;

  return (
    <div className="space-y-6">
      {/* Control Strip */}
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
        <div>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Real-time governance telemetry pulled directly from AXLY Chaperone endpoints.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setAutoRefresh((prev) => !prev)}
            className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors ${
              autoRefresh
                ? 'border-emerald-300 bg-emerald-50 text-emerald-700 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-300'
                : 'border-slate-200 bg-white text-slate-600 dark:border-slate-800 dark:bg-obsidian-900 dark:text-slate-400'
            }`}
          >
            <Activity className="h-3.5 w-3.5" />
            <span>Auto-refresh: {autoRefresh ? '30s' : 'Off'}</span>
          </button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              dashboardQuery.refetch();
              healthQuery.refetch();
              readinessQuery.refetch();
            }}
            isLoading={dashboardQuery.isFetching}
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      {/* KPI Grid */}
      {dashboardQuery.isLoading ? (
        <CardGridSkeleton count={8} />
      ) : dashboardQuery.isError ? (
        <ErrorState
          title="Unable to load gateway telemetry"
          error={dashboardQuery.error}
          onRetry={() => dashboardQuery.refetch()}
        />
      ) : (
        <>
          <section aria-label="Key governance metrics" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <MetricCard
              label="Registered Agents"
              value={metrics.registeredAgents}
              sublabel={`${formatNumber(metrics.activeAgents)} active identities`}
              icon={Bot}
              tone="info"
              to="/agents"
            />
            <MetricCard
              label="Active Agents"
              value={metrics.activeAgents}
              sublabel={`${formatNumber(metrics.registeredAgents - metrics.activeAgents)} disabled`}
              icon={CheckCircle2}
              tone="success"
              to="/agents?status=active"
            />
            <MetricCard
              label="Registered Tools"
              value={metrics.registeredTools}
              sublabel={`${formatNumber(metrics.enabledTools)} enabled in registry`}
              icon={Wrench}
              tone="info"
              to="/tools"
            />
            <MetricCard
              label="Enabled Tools"
              value={metrics.enabledTools}
              sublabel={`${formatNumber(metrics.registeredTools - metrics.enabledTools)} disabled`}
              icon={ShieldCheck}
              tone="success"
              to="/tools"
            />
            <MetricCard
              label="Pending Approvals"
              value={metrics.pendingApprovals}
              sublabel="Awaiting human review"
              icon={Clock}
              tone={metrics.pendingApprovals > 0 ? 'warning' : 'neutral'}
              to="/approvals"
            />

            <MetricCard
              label="Requests Evaluated"
              value={metrics.requestsEvaluated}
              sublabel={
                metrics.requestsEvaluatedIsExactFlows
                  ? `Unique flows (${metrics.totalAuditEvents} audit events)`
                  : 'Total audit trail records'
              }
              icon={Activity}
              tone="neutral"
              to="/audit-logs"
            />
            <MetricCard
              label="Allowed Requests"
              value={metrics.allowedRequests}
              sublabel={
                metrics.requestsEvaluatedIsExactFlows
                  ? 'Unique allowed flows'
                  : 'Allow decision events'
              }
              icon={ShieldCheck}
              tone="success"
              to="/audit-logs?decision=allow"
            />
            <MetricCard
              label="Blocked Requests"
              value={metrics.blockedRequests}
              sublabel={
                metrics.requestsEvaluatedIsExactFlows
                  ? 'Unique denied/blocked flows'
                  : 'Deny decision events'
              }
              icon={ShieldOff}
              tone={metrics.blockedRequests > 0 ? 'danger' : 'neutral'}
              to="/security-events?decision=deny"
            />
            <MetricCard
              label="Verified Executions"
              value={metrics.verifiedExecutions}
              sublabel="Independently state-confirmed"
              icon={CheckCircle2}
              tone="success"
              to="/audit-logs?event_type=verification_completed"
            />
            <MetricCard
              label="Failed Verifications"
              value={metrics.failedVerifications}
              sublabel="State verification mismatches"
              icon={XCircle}
              tone={metrics.failedVerifications > 0 ? 'danger' : 'neutral'}
              to="/security-events?verification_status=failed"
            />
          </section>

          {/* Charts Grid */}
          <section aria-label="Telemetry charts" className="grid gap-6 lg:grid-cols-2">
            <DecisionBreakdownChart
              data={data.charts.decisionBreakdown}
              isLoading={dashboardQuery.isLoading}
            />
            <ToolUsageChart
              data={data.charts.toolUsage}
              isLoading={dashboardQuery.isLoading}
              scopeLabel={chartScopeNote}
            />
            <SecurityTrendsChart
              data={data.charts.securityTrends}
              isLoading={dashboardQuery.isLoading}
              scopeLabel={chartScopeNote}
            />
            <ApprovalActivityChart
              data={data.charts.approvalActivity}
              isLoading={dashboardQuery.isLoading}
            />
          </section>

          {/* Operational Queues & Health */}
          <section className="grid gap-6 lg:grid-cols-3">
            {/* Pending Approvals */}
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>Pending Approvals</CardTitle>
                  <CardDescription>Human review required before execution</CardDescription>
                </div>
                <Link
                  to="/approvals"
                  className="text-xs font-medium text-sky-600 hover:text-sky-500 dark:text-sky-400"
                >
                  View all
                </Link>
              </CardHeader>
              <CardContent className="p-0">
                {data.feeds.pendingApprovals.length === 0 ? (
                  <EmptyState
                    icon={Clock}
                    title="Queue clear"
                    description="No pending approval requests require action."
                    className="py-8"
                  />
                ) : (
                  <ul className="divide-y divide-slate-200 dark:divide-slate-800/80">
                    {data.feeds.pendingApprovals.slice(0, 5).map((item) => {
                      const agent = lookups?.agentsById?.get(item.agent_id);
                      return (
                        <li key={item.id} className="px-5 py-3">
                          <div className="flex items-center justify-between gap-2">
                            <span className="truncate text-xs font-medium text-slate-900 dark:text-slate-100">
                              {agent?.name || shortenId(item.agent_id)}
                            </span>
                            <StatusBadge value={item.status} />
                          </div>
                          <div className="mt-1 flex items-center justify-between gap-2 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                            <span className="truncate">
                              {item.tool_name} · {item.action} → {item.resource}
                            </span>
                            <span className="shrink-0">{formatRelativeTime(item.expires_at)}</span>
                          </div>
                          <div className="mt-2">
                            <Link
                              to={`/approvals?highlight=${item.id}`}
                              className="text-[11px] font-medium text-sky-600 hover:text-sky-500 dark:text-sky-400"
                            >
                              Review request →
                            </Link>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>

            {/* Recent Security Events */}
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>Recent Security Events</CardTitle>
                  <CardDescription>Denied, blocked, auth, and approval triggers</CardDescription>
                </div>
                <Link
                  to="/security-events"
                  className="text-xs font-medium text-sky-600 hover:text-sky-500 dark:text-sky-400"
                >
                  View all
                </Link>
              </CardHeader>
              <CardContent className="p-0">
                {data.feeds.recentSecurityEvents.length === 0 ? (
                  <EmptyState
                    icon={ShieldAlert}
                    title="No security events"
                    description="Denied or high-risk security events will appear here."
                    className="py-8"
                  />
                ) : (
                  <ul className="divide-y divide-slate-200 dark:divide-slate-800/80">
                    {data.feeds.recentSecurityEvents.slice(0, 5).map((ev) => (
                      <li key={ev.id} className="px-5 py-3">
                        <div className="flex items-center justify-between gap-2">
                          <StatusBadge value={ev.decision} />
                          <span className="text-[11px] tabular-nums text-slate-500 dark:text-slate-400">
                            {formatShortTime(ev.created_at)}
                          </span>
                        </div>
                        <p className="mt-1.5 truncate font-mono text-[11px] text-slate-800 dark:text-slate-200">
                          {ev.tool_name}.{ev.action} ({ev.resource})
                        </p>
                        <p className="mt-0.5 truncate text-[11px] text-slate-500 dark:text-slate-400">
                          {ev.reason}
                        </p>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>

            {/* Recent Executions + System Health */}
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <div>
                    <CardTitle>Recent Executions</CardTitle>
                    <CardDescription>Latest adapter runs and verifications</CardDescription>
                  </div>
                  <Link
                    to="/audit-logs"
                    className="text-xs font-medium text-sky-600 hover:text-sky-500 dark:text-sky-400"
                  >
                    Audit Explorer
                  </Link>
                </CardHeader>
                <CardContent className="p-0">
                  {data.feeds.recentExecutions.length === 0 ? (
                    <EmptyState
                      icon={Wrench}
                      title="No executions recorded"
                      description="Completed and verified tool executions will appear here."
                      className="py-6"
                    />
                  ) : (
                    <ul className="divide-y divide-slate-200 dark:divide-slate-800/80">
                      {data.feeds.recentExecutions.slice(0, 4).map((ev) => (
                        <li key={ev.id} className="px-5 py-3">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono text-xs font-medium text-slate-900 dark:text-slate-100">
                              {ev.tool_name}.{ev.action}
                            </span>
                            <StatusBadge value={ev.verification_status} />
                          </div>
                          <div className="mt-1 flex items-center justify-between gap-2 text-[11px] text-slate-500 dark:text-slate-400">
                            <span className="truncate font-mono">{ev.resource}</span>
                            <span className="shrink-0 tabular-nums">
                              {formatShortTime(ev.created_at)}
                            </span>
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <div>
                    <CardTitle>System Health Status</CardTitle>
                    <CardDescription>Live API & database readiness probes</CardDescription>
                  </div>
                </CardHeader>
                <CardContent className="space-y-2.5 text-xs">
                  {healthQuery.isLoading ? (
                    <Skeleton className="h-14 w-full" />
                  ) : (
                    <>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-500 dark:text-slate-400">Gateway API (/health)</span>
                        <StatusBadge
                          value={healthQuery.isSuccess ? 'active' : 'failed'}
                          labelOverride={healthQuery.isSuccess ? 'HEALTHY' : 'UNREACHABLE'}
                        />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-500 dark:text-slate-400">Database (/ready)</span>
                        <StatusBadge
                          value={readinessQuery.data?.database === 'connected' ? 'verified' : 'failed'}
                          labelOverride={
                            readinessQuery.data?.database === 'connected' ? 'CONNECTED' : 'UNAVAILABLE'
                          }
                        />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-500 dark:text-slate-400">Service Version</span>
                        <span className="font-mono text-slate-900 dark:text-slate-100">
                          {healthQuery.data?.version ? `v${healthQuery.data.version}` : '—'}
                        </span>
                      </div>
                    </>
                  )}
                </CardContent>
              </Card>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
