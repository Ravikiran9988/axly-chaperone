import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, FileText, Power, ShieldCheck } from 'lucide-react';
import { useAgentQuery, useUpdateAgentStatusMutation } from '../hooks/useAgents';
import { usePoliciesQuery } from '../hooks/usePolicies';
import { useAuditEventsQuery } from '../hooks/useAuditEvents';
import { useApprovalsQuery } from '../hooks/useApprovals';
import { useToast } from '../context/ToastContext';
import { formatDateTime, formatShortTime, shortenId } from '../utils/formatters';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { CopyButton } from '../components/ui/CopyButton';
import { ErrorState } from '../components/ui/ErrorState';
import { EmptyState } from '../components/ui/EmptyState';
import { Skeleton, TableSkeleton } from '../components/ui/Skeleton';

export function AgentDetails() {
  const { agentId } = useParams();
  const toast = useToast();
  const [confirmToggle, setConfirmToggle] = useState(false);

  const agentQuery = useAgentQuery(agentId);
  const statusMutation = useUpdateAgentStatusMutation();
  const agentPoliciesQuery = usePoliciesQuery({ agent_id: agentId, page: 1, page_size: 100 });
  const allPoliciesQuery = usePoliciesQuery({ page: 1, page_size: 100 });
  const auditQuery = useAuditEventsQuery({ agent_id: agentId, page: 1, page_size: 20, order: 'desc' });
  const approvalsQuery = useApprovalsQuery({ agent_id: agentId, page: 1, page_size: 10 });

  const agent = agentQuery.data;
  const globalPolicies = (allPoliciesQuery.data?.items || []).filter((p) => p.agent_id === null);
  const agentPolicies = agentPoliciesQuery.data?.items || [];

  const handleConfirmToggle = async () => {
    if (!agent) return;
    const nextStatus = agent.status === 'active' ? 'disabled' : 'active';
    try {
      await statusMutation.mutateAsync({ agentId: agent.id, status: nextStatus });
      toast.success(
        nextStatus === 'active' ? 'Agent enabled' : 'Agent disabled',
        `Agent "${agent.name}" is now ${nextStatus}.`
      );
      setConfirmToggle(false);
    } catch (err) {
      toast.error('Failed to update status', err.message);
    }
  };

  if (agentQuery.isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (agentQuery.isError) {
    return <ErrorState title="Failed to load agent details" error={agentQuery.error} onRetry={() => agentQuery.refetch()} />;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Link
          to="/agents"
          className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to Agents
        </Link>
        <Button
          variant={agent.status === 'active' ? 'danger' : 'success'}
          size="sm"
          onClick={() => setConfirmToggle(true)}
        >
          <Power className="h-3.5 w-3.5" />
          {agent.status === 'active' ? 'Disable Agent' : 'Enable Agent'}
        </Button>
      </div>

      {/* Identity Overview */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <CardTitle className="text-base">{agent.name}</CardTitle>
            <StatusBadge value={agent.status} />
          </div>
          <div className="flex items-center gap-2 font-mono text-xs text-slate-500 dark:text-slate-400">
            <span>{agent.id}</span>
            <CopyButton value={agent.id} label="ID" iconOnly />
          </div>
        </CardHeader>
        <CardContent className="grid gap-4 text-xs sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <span className="text-slate-500 dark:text-slate-400">Key Prefix</span>
            <p className="mt-1 font-mono text-slate-900 dark:text-slate-100">{agent.key_prefix}</p>
          </div>
          <div>
            <span className="text-slate-500 dark:text-slate-400">Created</span>
            <p className="mt-1 tabular-nums text-slate-900 dark:text-slate-100">
              {formatDateTime(agent.created_at)}
            </p>
          </div>
          <div>
            <span className="text-slate-500 dark:text-slate-400">Updated</span>
            <p className="mt-1 tabular-nums text-slate-900 dark:text-slate-100">
              {formatDateTime(agent.updated_at)}
            </p>
          </div>
          <div>
            <span className="text-slate-500 dark:text-slate-400">Description</span>
            <p className="mt-1 text-slate-700 dark:text-slate-300">
              {agent.description || 'No description provided'}
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Associated Policies */}
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Associated Policies</CardTitle>
            <CardDescription>
              Agent-scoped rules ({agentPolicies.length}) and global rules ({globalPolicies.length}) evaluated for this agent
            </CardDescription>
          </div>
          <Link to="/policies">
            <Button variant="outline" size="xs">
              Manage Policies
            </Button>
          </Link>
        </CardHeader>
        <CardContent className="p-0">
          {agentPoliciesQuery.isLoading ? (
            <TableSkeleton rows={4} cols={5} />
          ) : agentPolicies.length === 0 && globalPolicies.length === 0 ? (
            <EmptyState
              icon={ShieldCheck}
              title="No policies apply to this agent"
              description="By default, zero matching policies result in DENY for all tool requests."
              className="py-8"
            />
          ) : (
            <div className="divide-y divide-slate-200 dark:divide-slate-800/80">
              {[...agentPolicies.map((p) => ({ ...p, _scope: 'Agent-Specific' })), ...globalPolicies.map((p) => ({ ...p, _scope: 'Global' }))].map(
                (policy) => (
                  <div
                    key={policy.id}
                    className="flex flex-col justify-between gap-2 px-5 py-3 text-xs sm:flex-row sm:items-center"
                  >
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-slate-900 dark:text-slate-100">
                          {policy.name}
                        </span>
                        <StatusBadge value={policy.decision} />
                        <span className="rounded border border-slate-200 px-1.5 py-0.5 text-[10px] text-slate-500 dark:border-slate-700 dark:text-slate-400">
                          {policy._scope}
                        </span>
                        {!policy.enabled && <StatusBadge value="disabled" />}
                      </div>
                      <p className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                        {policy.tool_name} · action={policy.action} · scope={policy.resource_scope}
                      </p>
                    </div>
                    <div className="flex items-center gap-3 text-[11px] tabular-nums text-slate-500 dark:text-slate-400">
                      <span>Priority: {policy.priority}</span>
                      <span>v{policy.version}</span>
                    </div>
                  </div>
                )
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Recent Activity & Approvals */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Recent Audit Activity</CardTitle>
              <CardDescription>Latest gateway events involving this agent</CardDescription>
            </div>
            <Link
              to={`/audit-logs?agent_id=${agent.id}`}
              className="text-xs font-medium text-sky-600 hover:text-sky-500 dark:text-sky-400"
            >
              View in Audit Logs
            </Link>
          </CardHeader>
          <CardContent className="p-0">
            {auditQuery.isLoading ? (
              <TableSkeleton rows={4} cols={3} />
            ) : (auditQuery.data?.items || []).length === 0 ? (
              <EmptyState
                icon={FileText}
                title="No activity recorded"
                description="This agent has not submitted any gateway requests yet."
                className="py-8"
              />
            ) : (
              <ul className="divide-y divide-slate-200 dark:divide-slate-800/80">
                {auditQuery.data.items.slice(0, 10).map((ev) => (
                  <li key={ev.id} className="px-5 py-3 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <StatusBadge value={ev.decision} />
                      <span className="tabular-nums text-[11px] text-slate-500 dark:text-slate-400">
                        {formatShortTime(ev.created_at)}
                      </span>
                    </div>
                    <p className="mt-1 font-mono text-[11px] text-slate-800 dark:text-slate-200">
                      {ev.tool_name}.{ev.action} → {ev.resource}
                    </p>
                    <div className="mt-1 flex items-center justify-between gap-2 text-[11px] text-slate-500 dark:text-slate-400">
                      <span className="truncate">{ev.event_type}</span>
                      <Link
                        to={`/audit-logs?correlation_id=${encodeURIComponent(ev.correlation_id)}`}
                        className="shrink-0 font-mono text-sky-600 hover:underline dark:text-sky-400"
                      >
                        {shortenId(ev.correlation_id)}
                      </Link>
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
              <CardTitle>Agent Approval Requests</CardTitle>
              <CardDescription>Recent human approval gates triggered by this agent</CardDescription>
            </div>
            <Link
              to={`/approvals?agent_id=${agent.id}`}
              className="text-xs font-medium text-sky-600 hover:text-sky-500 dark:text-sky-400"
            >
              Open Approvals
            </Link>
          </CardHeader>
          <CardContent className="p-0">
            {approvalsQuery.isLoading ? (
              <TableSkeleton rows={4} cols={3} />
            ) : (approvalsQuery.data?.items || []).length === 0 ? (
              <EmptyState
                title="No approval history"
                description="Approval requests generated by this agent will appear here."
                className="py-8"
              />
            ) : (
              <ul className="divide-y divide-slate-200 dark:divide-slate-800/80">
                {approvalsQuery.data.items.map((ap) => (
                  <li key={ap.id} className="px-5 py-3 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono font-medium text-slate-900 dark:text-slate-100">
                        {ap.tool_name}.{ap.action}
                      </span>
                      <StatusBadge value={ap.status} />
                    </div>
                    <p className="mt-1 truncate font-mono text-[11px] text-slate-500 dark:text-slate-400">
                      {ap.resource}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      <ConfirmDialog
        open={confirmToggle}
        onClose={() => setConfirmToggle(false)}
        onConfirm={handleConfirmToggle}
        isLoading={statusMutation.isPending}
        variant={agent.status === 'active' ? 'danger' : 'success'}
        title={agent.status === 'active' ? 'Disable Agent?' : 'Enable Agent?'}
        confirmLabel={agent.status === 'active' ? 'Disable Agent' : 'Enable Agent'}
        message={
          agent.status === 'active'
            ? `Disabling "${agent.name}" immediately rejects any incoming gateway or MCP requests using its API key.`
            : `Enabling "${agent.name}" restores gateway access subject to active security policies.`
        }
      />
    </div>
  );
}
