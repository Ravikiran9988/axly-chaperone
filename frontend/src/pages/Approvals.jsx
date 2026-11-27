import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  AlertTriangle,
  CheckCircle2,
  CheckSquare,
  Clock,
  Eye,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import {
  useApprovalQuery,
  useApprovalsQuery,
  useApproveMutation,
  useRejectMutation,
} from '../hooks/useApprovals';
import { useAgentsQuery } from '../hooks/useAgents';
import { useToolsQuery } from '../hooks/useTools';
import { useAuditEventsQuery, useCorrelationTimelineQuery } from '../hooks/useAuditEvents';
import { useToast } from '../context/ToastContext';
import {
  formatDateTime,
  formatRelativeTime,
  isExpiredTimestamp,
  shortenId,
} from '../utils/formatters';
import { redactSensitivePayload } from '../utils/redaction';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { Pagination } from '../components/ui/Pagination';
import { Drawer } from '../components/ui/Drawer';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { CopyButton } from '../components/ui/CopyButton';
import { Textarea } from '../components/ui/Input';
import { DataTable } from '../components/tables/DataTable';

const STATUS_TABS = [
  { value: 'pending', label: 'Pending' },
  { value: '', label: 'All' },
  { value: 'executed', label: 'Executed' },
  { value: 'approved', label: 'Approved' },
  { value: 'rejected', label: 'Rejected' },
  { value: 'expired', label: 'Expired' },
  { value: 'failed', label: 'Failed' },
];

export function Approvals() {
  const [searchParams, setSearchParams] = useSearchParams();
  const toast = useToast();

  const highlightId = searchParams.get('highlight') || '';
  const initialAgent = searchParams.get('agent_id') || '';

  const [statusFilter, setStatusFilter] = useState(highlightId ? '' : 'pending');
  const [agentFilter, setAgentFilter] = useState(initialAgent);
  const [toolFilter, setToolFilter] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 20;

  const [selectedId, setSelectedId] = useState(highlightId || null);
  const [comment, setComment] = useState('');
  const [confirmAction, setConfirmAction] = useState(null); // { type: 'approve'|'reject', executeNow: boolean }
  const [lastActionResult, setLastActionResult] = useState(null);

  useEffect(() => {
    if (highlightId) {
      setSelectedId(highlightId);
      setStatusFilter('');
    }
  }, [highlightId]);

  const approvalsQuery = useApprovalsQuery({
    page,
    page_size: pageSize,
    status: statusFilter || undefined,
    agent_id: agentFilter || undefined,
    tool_name: toolFilter || undefined,
  });
  const detailQuery = useApprovalQuery(selectedId);
  const agentsQuery = useAgentsQuery({ page: 1, page_size: 100 });
  const toolsQuery = useToolsQuery({ page: 1, page_size: 100 });
  const policyAuditReasonsQuery = useAuditEventsQuery({
    decision: 'require_approval',
    page: 1,
    page_size: 100,
    order: 'desc',
  });

  const selectedApproval =
    detailQuery.data ||
    (approvalsQuery.data?.items || []).find((item) => item.id === selectedId) ||
    null;

  const correlationAuditQuery = useCorrelationTimelineQuery(selectedApproval?.correlation_id);

  const approveMutation = useApproveMutation();
  const rejectMutation = useRejectMutation();

  const agents = agentsQuery.data?.items || [];
  const tools = toolsQuery.data?.items || [];
  const agentMap = useMemo(() => new Map(agents.map((a) => [a.id, a])), [agents]);
  const toolMap = useMemo(() => new Map(tools.map((t) => [t.name, t])), [tools]);
  const reasonByCorrelation = useMemo(() => {
    const map = new Map();
    for (const ev of policyAuditReasonsQuery.data?.items || []) {
      if (ev.event_type === 'policy_evaluation' || !map.has(ev.correlation_id)) {
        map.set(ev.correlation_id, ev.reason);
      }
    }
    return map;
  }, [policyAuditReasonsQuery.data]);

  const selectedPolicyEvent = useMemo(() => {
    const events = correlationAuditQuery.data?.items || [];
    return (
      events.find((e) => e.event_type === 'policy_evaluation') ||
      events.find((e) => e.event_type === 'approval_requested') ||
      null
    );
  }, [correlationAuditQuery.data]);

  const handleOpenApproval = (approval) => {
    setSelectedId(approval.id);
    setComment('');
    setLastActionResult(null);
  };

  const handleCloseDrawer = () => {
    setSelectedId(null);
    setComment('');
    setLastActionResult(null);
    if (searchParams.has('highlight')) {
      const next = new URLSearchParams(searchParams);
      next.delete('highlight');
      setSearchParams(next);
    }
  };

  const handleConfirmDecision = async () => {
    if (!selectedApproval || !confirmAction) return;
    try {
      if (confirmAction.type === 'approve') {
        const res = await approveMutation.mutateAsync({
          approvalId: selectedApproval.id,
          comment,
          executeNow: confirmAction.executeNow,
        });
        setLastActionResult(res);
        toast.success(
          res.execution_status === 'EXECUTED'
            ? 'Approved, executed & verified'
            : res.execution_status === 'FAILED'
              ? 'Approved, execution failed'
              : 'Request approved',
          `Approval ${shortenId(selectedApproval.id)} resolved (${res.approval.status.toUpperCase()}).`
        );
      } else {
        const res = await rejectMutation.mutateAsync({
          approvalId: selectedApproval.id,
          comment,
        });
        setLastActionResult(res);
        toast.warning(
          'Request rejected',
          `Approval ${shortenId(selectedApproval.id)} rejected; tool was never executed.`
        );
      }
      setConfirmAction(null);
      setComment('');
    } catch (err) {
      setConfirmAction(null);
      toast.error('Approval action failed', err.message);
      approvalsQuery.refetch();
      detailQuery.refetch();
    }
  };

  const columns = [
    {
      key: 'agent',
      header: 'Agent',
      render: (ap) => {
        const agent = agentMap.get(ap.agent_id);
        return (
          <div>
            <div className="font-medium text-slate-900 dark:text-slate-100">
              {agent?.name || shortenId(ap.agent_id)}
            </div>
            <div className="font-mono text-[10px] text-slate-500 dark:text-slate-400">
              {agent?.key_prefix || ap.agent_id}
            </div>
          </div>
        );
      },
    },
    {
      key: 'tool',
      header: 'Tool · Action · Resource',
      render: (ap) => {
        const tool = toolMap.get(ap.tool_name);
        return (
          <div className="max-w-xs space-y-1">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100">
                {ap.tool_name}.{ap.action}
              </span>
              {tool && <StatusBadge value={tool.risk_level} />}
            </div>
            <p className="truncate font-mono text-[11px] text-slate-600 dark:text-slate-400">
              {ap.resource}
            </p>
            {reasonByCorrelation.get(ap.correlation_id) && (
              <p className="truncate text-[11px] text-slate-500 dark:text-slate-400">
                {reasonByCorrelation.get(ap.correlation_id)}
              </p>
            )}
          </div>
        );
      },
    },
    {
      key: 'status',
      header: 'Status',
      render: (ap) => <StatusBadge value={ap.status} />,
    },
    {
      key: 'requested_at',
      header: 'Requested / Expires',
      render: (ap) => {
        const elapsed = ap.status === 'pending' && isExpiredTimestamp(ap.expires_at);
        return (
          <div className="space-y-0.5 whitespace-nowrap text-[11px] tabular-nums">
            <div className="text-slate-700 dark:text-slate-300">
              {formatDateTime(ap.requested_at)}
            </div>
            <div
              className={
                elapsed
                  ? 'font-medium text-rose-600 dark:text-rose-400'
                  : 'text-slate-500 dark:text-slate-400'
              }
            >
              {ap.status === 'pending'
                ? elapsed
                  ? `Expired (${formatRelativeTime(ap.expires_at)})`
                  : `Expires ${formatRelativeTime(ap.expires_at)}`
                : `Expires ${formatDateTime(ap.expires_at)}`}
            </div>
          </div>
        );
      },
    },
    {
      key: 'actions',
      header: 'Review',
      headerClassName: 'text-right',
      cellClassName: 'text-right',
      render: (ap) => (
        <Button
          variant={ap.status === 'pending' ? 'primary' : 'ghost'}
          size="xs"
          onClick={() => handleOpenApproval(ap)}
        >
          <Eye className="h-3.5 w-3.5" />
          {ap.status === 'pending' ? 'Review' : 'Details'}
        </Button>
      ),
    },
  ];

  const isPendingApproval = selectedApproval?.status === 'pending';
  const clientElapsed = isPendingApproval && isExpiredTimestamp(selectedApproval?.expires_at);
  const redactedPayload = useMemo(
    () => redactSensitivePayload(selectedApproval?.sanitized_arguments || {}),
    [selectedApproval]
  );

  return (
    <div className="space-y-5">
      <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-center">
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Human-in-the-loop governance queue for sensitive actions gated by <code>REQUIRE_APPROVAL</code> policies. Payloads are SHA-256 bound to prevent tampering.
        </p>
      </div>

      {/* Status Filter Tabs */}
      <div className="flex flex-wrap gap-1.5 border-b border-slate-200 pb-3 dark:border-slate-800/80">
        {STATUS_TABS.map((tab) => (
          <button
            key={tab.label}
            type="button"
            onClick={() => {
              setStatusFilter(tab.value);
              setPage(1);
            }}
            className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              statusFilter === tab.value
                ? 'bg-sky-600 text-white dark:bg-sky-500 dark:text-slate-950'
                : 'bg-white text-slate-600 hover:bg-slate-100 dark:bg-obsidian-900 dark:text-slate-400 dark:hover:bg-obsidian-800 dark:hover:text-slate-100'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 p-4 dark:border-slate-800/80">
          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label="Filter approvals by agent"
              value={agentFilter}
              onChange={(e) => {
                setAgentFilter(e.target.value);
                setPage(1);
              }}
              className="rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
            >
              <option value="">All Agents</option>
              {agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>

            <select
              aria-label="Filter approvals by tool"
              value={toolFilter}
              onChange={(e) => {
                setToolFilter(e.target.value);
                setPage(1);
              }}
              className="rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
            >
              <option value="">All Tools</option>
              {tools.map((t) => (
                <option key={t.name} value={t.name}>
                  {t.name}
                </option>
              ))}
            </select>
          </div>
          <span className="text-xs tabular-nums text-slate-500 dark:text-slate-400">
            Total matching: {approvalsQuery.data?.total ?? 0}
          </span>
        </div>

        <DataTable
          columns={columns}
          rows={approvalsQuery.data?.items || []}
          isLoading={approvalsQuery.isLoading}
          error={approvalsQuery.error}
          onRetry={() => approvalsQuery.refetch()}
          emptyIcon={CheckSquare}
          emptyTitle={
            statusFilter === 'pending' ? 'No pending approval requests' : 'No approval records found'
          }
          emptyDescription="When an agent attempts an action matching a REQUIRE_APPROVAL policy, it appears here for review."
        />

        <Pagination
          page={page}
          pageSize={pageSize}
          total={approvalsQuery.data?.total || 0}
          totalPages={approvalsQuery.data?.total_pages || 0}
          onPageChange={setPage}
        />
      </Card>

      {/* Approval Inspection & Decision Drawer */}
      <Drawer
        open={Boolean(selectedApproval)}
        onClose={handleCloseDrawer}
        title="Approval Request Inspection"
        subtitle={selectedApproval ? `ID: ${selectedApproval.id}` : ''}
        width="xl"
      >
        {selectedApproval && (
          <div className="space-y-5 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge value={selectedApproval.status} />
                {toolMap.get(selectedApproval.tool_name) && (
                  <StatusBadge value={toolMap.get(selectedApproval.tool_name).risk_level} />
                )}
              </div>
              <Link
                to={`/audit-logs?correlation_id=${encodeURIComponent(selectedApproval.correlation_id)}`}
                className="font-mono text-[11px] text-sky-600 hover:underline dark:text-sky-400"
              >
                Trace Correlation ({shortenId(selectedApproval.correlation_id)}) →
              </Link>
            </div>

            {clientElapsed && (
              <div className="flex items-start gap-2 rounded-md border border-amber-300 bg-amber-50 p-3 text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200">
                <Clock className="mt-0.5 h-4 w-4 shrink-0" />
                <span>
                  This approval&apos;s TTL ({formatDateTime(selectedApproval.expires_at)}) appears
                  elapsed. Attempting approval will atomically transition it to EXPIRED.
                </span>
              </div>
            )}

            {/* Metadata grid */}
            <div className="grid gap-3 rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-obsidian-950 sm:grid-cols-2">
              <div>
                <span className="text-slate-500 dark:text-slate-400">Agent Identity</span>
                <p className="mt-0.5 font-medium text-slate-900 dark:text-slate-100">
                  {agentMap.get(selectedApproval.agent_id)?.name || 'Unknown Agent'}
                </p>
                <p className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                  {selectedApproval.agent_id}
                </p>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400">Tool & Action</span>
                <p className="mt-0.5 font-mono font-semibold text-slate-900 dark:text-slate-100">
                  {selectedApproval.tool_name} · {selectedApproval.action}
                </p>
              </div>
              <div className="sm:col-span-2">
                <span className="text-slate-500 dark:text-slate-400">Target Resource</span>
                <div className="mt-1 flex items-center justify-between gap-2 rounded border border-slate-200 bg-white px-2.5 py-1.5 dark:border-slate-800 dark:bg-obsidian-900">
                  <code className="break-all font-mono text-slate-900 dark:text-slate-100">
                    {selectedApproval.resource}
                  </code>
                  <CopyButton value={selectedApproval.resource} label="Resource" iconOnly />
                </div>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400">Requested At</span>
                <p className="mt-0.5 tabular-nums">{formatDateTime(selectedApproval.requested_at)}</p>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400">Expires At</span>
                <p className="mt-0.5 tabular-nums">{formatDateTime(selectedApproval.expires_at)}</p>
              </div>
              <div className="sm:col-span-2">
                <span className="text-slate-500 dark:text-slate-400">Policy Reason</span>
                <p className="mt-0.5 text-slate-800 dark:text-slate-200">
                  {selectedPolicyEvent?.reason ||
                    (correlationAuditQuery.isLoading
                      ? 'Loading policy rationale from audit log...'
                      : 'Policy reason unavailable in audit log.')}
                </p>
              </div>
            </div>

            {/* Immutable Sanitized Payload */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <h4 className="font-semibold text-slate-900 dark:text-slate-100">
                  Immutable Request Payload (Redacted)
                </h4>
                <span className="text-[11px] text-slate-500 dark:text-slate-400">
                  SHA-256 bound on server
                </span>
              </div>
              <pre className="max-h-60 overflow-auto rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] text-slate-800 dark:border-slate-800 dark:bg-obsidian-950 dark:text-slate-200">
                {JSON.stringify(redactedPayload, null, 2)}
              </pre>
            </div>

            {/* Immediate post-action verification output */}
            {lastActionResult && (
              <div className="space-y-2 rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-obsidian-950">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-900 dark:text-slate-100">
                    Resolution Result
                  </span>
                  <StatusBadge value={lastActionResult.approval?.status} />
                </div>
                {lastActionResult.verification && (
                  <div className="flex items-start gap-2 rounded border border-slate-200 bg-white p-2.5 dark:border-slate-800 dark:bg-obsidian-900">
                    <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">Verification:</span>
                        <StatusBadge value={lastActionResult.verification.status} />
                      </div>
                      <p className="mt-1 text-slate-600 dark:text-slate-300">
                        {lastActionResult.verification.message}
                      </p>
                    </div>
                  </div>
                )}
                {lastActionResult.output && (
                  <pre className="max-h-40 overflow-auto rounded border border-slate-200 bg-white p-2.5 font-mono text-[11px] dark:border-slate-800 dark:bg-obsidian-900">
                    {JSON.stringify(redactSensitivePayload(lastActionResult.output), null, 2)}
                  </pre>
                )}
              </div>
            )}

            {/* Resolution audit metadata for resolved approvals */}
            {selectedApproval.status !== 'pending' && (
              <div className="space-y-2 rounded-lg border border-slate-200 p-4 dark:border-slate-800">
                <h4 className="font-semibold text-slate-900 dark:text-slate-100">
                  Review & Execution Record
                </h4>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <span className="text-slate-500 dark:text-slate-400">Reviewer ID</span>
                    <p className="mt-0.5 font-mono">{selectedApproval.reviewer_id || '—'}</p>
                  </div>
                  <div>
                    <span className="text-slate-500 dark:text-slate-400">Reviewed At</span>
                    <p className="mt-0.5 tabular-nums">
                      {formatDateTime(selectedApproval.reviewed_at)}
                    </p>
                  </div>
                  <div className="sm:col-span-2">
                    <span className="text-slate-500 dark:text-slate-400">Reviewer Comment</span>
                    <p className="mt-0.5">{selectedApproval.reviewer_comment || '—'}</p>
                  </div>
                </div>
                {selectedApproval.execution_result_reference && (
                  <div>
                    <span className="text-slate-500 dark:text-slate-400">
                      Execution & Verification Reference
                    </span>
                    <pre className="mt-1 max-h-40 overflow-auto rounded border border-slate-200 bg-slate-50 p-2.5 font-mono text-[11px] dark:border-slate-800 dark:bg-obsidian-950">
                      {JSON.stringify(
                        redactSensitivePayload(selectedApproval.execution_result_reference),
                        null,
                        2
                      )}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {/* Review Decision Controls (strictly shown for PENDING requests only) */}
            {isPendingApproval && (
              <div className="space-y-4 rounded-lg border border-slate-200 p-4 dark:border-slate-800">
                <Textarea
                  label="Reviewer Comment (optional)"
                  placeholder="Document rationale for approving or rejecting this request..."
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  rows={2}
                />

                <div className="flex flex-wrap items-center justify-between gap-2">
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={() => setConfirmAction({ type: 'reject', executeNow: false })}
                  >
                    <XCircle className="h-3.5 w-3.5" />
                    Reject Request
                  </Button>

                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setConfirmAction({ type: 'approve', executeNow: false })}
                    >
                      Approve Only (2-Step)
                    </Button>
                    <Button
                      variant="success"
                      size="sm"
                      onClick={() => setConfirmAction({ type: 'approve', executeNow: true })}
                    >
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      Approve & Execute Now
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={Boolean(confirmAction)}
        onClose={() => setConfirmAction(null)}
        onConfirm={handleConfirmDecision}
        isLoading={approveMutation.isPending || rejectMutation.isPending}
        variant={confirmAction?.type === 'reject' ? 'danger' : 'success'}
        title={
          confirmAction?.type === 'reject'
            ? 'Confirm Rejection'
            : confirmAction?.executeNow
              ? 'Confirm Approval & Immediate Execution'
              : 'Confirm 2-Step Approval'
        }
        confirmLabel={
          confirmAction?.type === 'reject'
            ? 'Reject Request'
            : confirmAction?.executeNow
              ? 'Approve & Execute'
              : 'Approve Only'
        }
        message={
          confirmAction?.type === 'reject'
            ? `Rejecting this request permanently blocks execution of ${selectedApproval?.tool_name}.${selectedApproval?.action} on "${selectedApproval?.resource}".`
            : confirmAction?.executeNow
              ? `Approving will immediately re-evaluate policies, dispatch ${selectedApproval?.tool_name}.${selectedApproval?.action} on "${selectedApproval?.resource}" once, and verify the resulting state.`
              : `Approving marks this request APPROVED so the agent can execute it once using approval_id with strict payload-hash verification.`
        }
        details={
          <div className="rounded border border-slate-200 bg-slate-50 px-2.5 py-2 text-[11px] dark:border-slate-800 dark:bg-obsidian-950">
            <div className="flex items-center gap-1.5 text-slate-600 dark:text-slate-300">
              <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
              <span>This governance decision is audited and cannot be undone.</span>
            </div>
          </div>
        }
      />
    </div>
  );
}
