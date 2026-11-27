import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ArrowRight, Clock, FileText, GitCommit, Search } from 'lucide-react';
import { useAuditEventsQuery, useCorrelationTimelineQuery } from '../hooks/useAuditEvents';
import { useAgentsQuery } from '../hooks/useAgents';
import { useToolsQuery } from '../hooks/useTools';
import { formatDateTime, shortenId } from '../utils/formatters';
import { redactSensitivePayload } from '../utils/redaction';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { Pagination } from '../components/ui/Pagination';
import { Drawer } from '../components/ui/Drawer';
import { CopyButton } from '../components/ui/CopyButton';
import { Skeleton } from '../components/ui/Skeleton';
import { DataTable } from '../components/tables/DataTable';

const STAGE_LABELS = {
  authentication: 'Authentication Gate',
  gateway_evaluate: 'Gateway Policy Evaluation',
  gateway_execute: 'Gateway Execution Check',
  policy_evaluation: 'Policy Decision',
  approval_requested: 'Human Approval Requested',
  approval_approved: 'Human Approval Granted',
  approval_rejected: 'Human Approval Rejected',
  approval_expired: 'Approval Expired',
  execution_started: 'Execution Dispatched',
  execution_completed: 'Execution Completed',
  execution_failed: 'Execution Failed',
  verification_completed: 'Independent Verification',
};

export function AuditLogs() {
  const [searchParams, setSearchParams] = useSearchParams();

  const [correlationFilter, setCorrelationFilter] = useState(
    searchParams.get('correlation_id') || ''
  );
  const [agentFilter, setAgentFilter] = useState(searchParams.get('agent_id') || '');
  const [toolFilter, setToolFilter] = useState(searchParams.get('tool_name') || '');
  const [decisionFilter, setDecisionFilter] = useState(searchParams.get('decision') || '');
  const [eventTypeFilter, setEventTypeFilter] = useState(searchParams.get('event_type') || '');
  const [order, setOrder] = useState('desc');
  const [searchTerm, setSearchTerm] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 25;

  const [timelineCid, setTimelineCid] = useState(searchParams.get('correlation_id') || null);
  const [inspectEvent, setInspectEvent] = useState(null);

  useEffect(() => {
    const cid = searchParams.get('correlation_id');
    if (cid) {
      setCorrelationFilter(cid);
      setTimelineCid(cid);
    }
  }, [searchParams]);

  const auditQuery = useAuditEventsQuery({
    page,
    page_size: pageSize,
    correlation_id: correlationFilter.trim() || undefined,
    agent_id: agentFilter || undefined,
    tool_name: toolFilter || undefined,
    decision: decisionFilter || undefined,
    event_type: eventTypeFilter || undefined,
    order,
  });

  const timelineQuery = useCorrelationTimelineQuery(timelineCid);
  const agentsQuery = useAgentsQuery({ page: 1, page_size: 100 });
  const toolsQuery = useToolsQuery({ page: 1, page_size: 100 });
  const agentMap = useMemo(
    () => new Map((agentsQuery.data?.items || []).map((a) => [a.id, a])),
    [agentsQuery.data]
  );

  const filteredRows = useMemo(() => {
    const rows = auditQuery.data?.items || [];
    const q = searchTerm.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter(
      (ev) =>
        ev.resource.toLowerCase().includes(q) ||
        ev.action.toLowerCase().includes(q) ||
        ev.tool_name.toLowerCase().includes(q) ||
        ev.reason.toLowerCase().includes(q) ||
        ev.correlation_id.toLowerCase().includes(q)
    );
  }, [auditQuery.data, searchTerm]);

  const handleCloseTimeline = () => {
    setTimelineCid(null);
    if (searchParams.has('correlation_id')) {
      const next = new URLSearchParams(searchParams);
      next.delete('correlation_id');
      setSearchParams(next);
    }
  };

  const columns = [
    {
      key: 'created_at',
      header: 'Timestamp',
      render: (ev) => (
        <span className="whitespace-nowrap tabular-nums text-[11px] text-slate-600 dark:text-slate-400">
          {formatDateTime(ev.created_at)}
        </span>
      ),
    },
    {
      key: 'correlation_id',
      header: 'Correlation ID',
      render: (ev) => (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            setTimelineCid(ev.correlation_id);
          }}
          className="font-mono text-[11px] font-medium text-sky-600 hover:underline dark:text-sky-400"
          title={`View timeline for ${ev.correlation_id}`}
        >
          {shortenId(ev.correlation_id)}
        </button>
      ),
    },
    {
      key: 'agent_id',
      header: 'Agent',
      render: (ev) => {
        if (!ev.agent_id) return <span className="text-[11px] text-slate-400">Anonymous</span>;
        const ag = agentMap.get(ev.agent_id);
        return (
          <span className="text-xs font-medium text-slate-800 dark:text-slate-200">
            {ag?.name || shortenId(ev.agent_id)}
          </span>
        );
      },
    },
    {
      key: 'tool_action',
      header: 'Tool · Action',
      render: (ev) => (
        <div className="font-mono text-[11px]">
          <span className="font-semibold text-slate-900 dark:text-slate-100">{ev.tool_name}</span>
          <span className="text-slate-400">.</span>
          <span className="text-sky-600 dark:text-sky-400">{ev.action}</span>
        </div>
      ),
    },
    {
      key: 'resource',
      header: 'Resource',
      render: (ev) => (
        <span className="block max-w-[200px] truncate font-mono text-[11px] text-slate-600 dark:text-slate-300">
          {ev.resource}
        </span>
      ),
    },
    {
      key: 'decision',
      header: 'Decision',
      render: (ev) => <StatusBadge value={ev.decision} />,
    },
    {
      key: 'execution_status',
      header: 'Execution',
      render: (ev) => <StatusBadge value={ev.execution_status} />,
    },
    {
      key: 'verification_status',
      header: 'Verification',
      render: (ev) => <StatusBadge value={ev.verification_status} />,
    },
  ];

  return (
    <div className="space-y-5">
      <p className="text-xs text-slate-500 dark:text-slate-400">
        Append-only immutable audit trail. Click any Correlation ID to inspect the exact recorded chronological execution lifecycle.
      </p>

      <Card>
        <div className="grid gap-3 border-b border-slate-200 p-4 dark:border-slate-800/80 md:grid-cols-3 lg:grid-cols-6">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
            <input
              type="search"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter page text..."
              aria-label="Search audit events"
              className="w-full rounded-md border border-slate-300 bg-white py-1.5 pl-8 pr-3 text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
            />
          </div>

          <input
            type="text"
            value={correlationFilter}
            onChange={(e) => {
              setCorrelationFilter(e.target.value);
              setPage(1);
            }}
            placeholder="Correlation ID..."
            aria-label="Correlation ID filter"
            className="rounded-md border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
          />

          <select
            aria-label="Filter by agent"
            value={agentFilter}
            onChange={(e) => {
              setAgentFilter(e.target.value);
              setPage(1);
            }}
            className="rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
          >
            <option value="">All Agents</option>
            {(agentsQuery.data?.items || []).map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>

          <select
            aria-label="Filter by tool"
            value={toolFilter}
            onChange={(e) => {
              setToolFilter(e.target.value);
              setPage(1);
            }}
            className="rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
          >
            <option value="">All Tools</option>
            {(toolsQuery.data?.items || []).map((t) => (
              <option key={t.name} value={t.name}>
                {t.name}
              </option>
            ))}
          </select>

          <select
            aria-label="Filter by decision"
            value={decisionFilter}
            onChange={(e) => {
              setDecisionFilter(e.target.value);
              setPage(1);
            }}
            className="rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
          >
            <option value="">All Decisions</option>
            <option value="allow">ALLOW</option>
            <option value="deny">DENY</option>
            <option value="require_approval">REQUIRE_APPROVAL</option>
          </select>

          <div className="flex gap-2">
            <select
              aria-label="Filter by event type"
              value={eventTypeFilter}
              onChange={(e) => {
                setEventTypeFilter(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-md border border-slate-300 bg-white px-2 py-1.5 text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
            >
              <option value="">Event Type: All</option>
              {Object.entries(STAGE_LABELS).map(([val, label]) => (
                <option key={val} value={val}>
                  {label}
                </option>
              ))}
            </select>

            <select
              aria-label="Sort order"
              value={order}
              onChange={(e) => {
                setOrder(e.target.value);
                setPage(1);
              }}
              className="rounded-md border border-slate-300 bg-white px-2 py-1.5 text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
            >
              <option value="desc">Newest</option>
              <option value="asc">Oldest</option>
            </select>
          </div>
        </div>

        <DataTable
          columns={columns}
          rows={filteredRows}
          isLoading={auditQuery.isLoading}
          error={auditQuery.error}
          onRetry={() => auditQuery.refetch()}
          onRowClick={(ev) => setInspectEvent(ev)}
          emptyIcon={FileText}
          emptyTitle="No audit events found"
          emptyDescription="Immutable gateway, approval, execution, and verification events will appear here."
        />

        <Pagination
          page={page}
          pageSize={pageSize}
          total={auditQuery.data?.total || 0}
          totalPages={auditQuery.data?.total_pages || 0}
          onPageChange={setPage}
        />
      </Card>

      {/* Chronological Execution Timeline Drawer */}
      <Drawer
        open={Boolean(timelineCid)}
        onClose={handleCloseTimeline}
        title="Chronological Execution Lifecycle"
        subtitle={timelineCid ? `Correlation ID: ${timelineCid}` : ''}
        width="xl"
      >
        <div className="space-y-4 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-slate-200 bg-slate-50 px-3.5 py-2.5 dark:border-slate-800 dark:bg-obsidian-950">
            <div className="flex items-center gap-2 font-mono text-[11px]">
              <span className="text-slate-500 dark:text-slate-400">Correlation:</span>
              <span className="text-slate-900 dark:text-slate-100">{timelineCid}</span>
            </div>
            <CopyButton value={timelineCid} label="Copy CID" />
          </div>

          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            Displays only persisted append-only audit events recorded by the gateway for this
            correlation ID in chronological order. Missing stages are never synthesized.
          </p>

          {timelineQuery.isLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-20 w-full" />
              <Skeleton className="h-20 w-full" />
            </div>
          ) : timelineQuery.isError ? (
            <p className="text-rose-500">{timelineQuery.error?.message}</p>
          ) : (timelineQuery.data?.items || []).length === 0 ? (
            <p className="py-8 text-center text-slate-500">
              No persisted audit events found for this correlation ID.
            </p>
          ) : (
            <ol className="relative space-y-4 border-l-2 border-slate-200 pl-5 dark:border-slate-800">
              {timelineQuery.data.items.map((ev, index) => (
                <li key={ev.id} className="relative">
                  <span className="absolute -left-[27px] top-1 flex h-4 w-4 items-center justify-center rounded-full border border-sky-500 bg-white text-sky-500 dark:bg-obsidian-900">
                    <GitCommit className="h-3 w-3" />
                  </span>
                  <div className="rounded-lg border border-slate-200 bg-white p-3.5 dark:border-slate-800 dark:bg-obsidian-950">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-semibold text-slate-900 dark:text-slate-100">
                          {index + 1}. {STAGE_LABELS[ev.event_type] || ev.event_type}
                        </span>
                        <StatusBadge value={ev.decision} />
                        <StatusBadge value={ev.execution_status} />
                        <StatusBadge value={ev.verification_status} />
                      </div>
                      <span className="flex items-center gap-1 tabular-nums text-[11px] text-slate-500 dark:text-slate-400">
                        <Clock className="h-3 w-3" />
                        {formatDateTime(ev.created_at)}
                      </span>
                    </div>

                    <p className="mt-2 text-slate-700 dark:text-slate-300">{ev.reason}</p>

                    <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                      <span>
                        target={ev.tool_name}.{ev.action} ({ev.resource})
                      </span>
                      {ev.policy_id && (
                        <span>
                          policy={shortenId(ev.policy_id)} v{ev.policy_version}
                        </span>
                      )}
                      {ev.reviewer_id && <span>reviewer={ev.reviewer_id}</span>}
                      {ev.verification_outcome && (
                        <span>outcome={ev.verification_outcome.toUpperCase()}</span>
                      )}
                    </div>

                    {(ev.policy_metadata || ev.execution_metadata) && (
                      <div className="mt-2.5 grid gap-2 sm:grid-cols-2">
                        {ev.policy_metadata && (
                          <pre className="overflow-auto rounded border border-slate-200 bg-slate-50 p-2 font-mono text-[10px] dark:border-slate-800 dark:bg-obsidian-900">
                            {JSON.stringify(redactSensitivePayload(ev.policy_metadata), null, 2)}
                          </pre>
                        )}
                        {ev.execution_metadata && (
                          <pre className="overflow-auto rounded border border-slate-200 bg-slate-50 p-2 font-mono text-[10px] dark:border-slate-800 dark:bg-obsidian-900">
                            {JSON.stringify(redactSensitivePayload(ev.execution_metadata), null, 2)}
                          </pre>
                        )}
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </div>
      </Drawer>

      {/* Single Event Inspection Drawer */}
      <Drawer
        open={Boolean(inspectEvent)}
        onClose={() => setInspectEvent(null)}
        title="Audit Event Record"
        subtitle={inspectEvent ? `Event ${inspectEvent.id}` : ''}
      >
        {inspectEvent && (
          <div className="space-y-4 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge value={inspectEvent.decision} />
              <StatusBadge value={inspectEvent.execution_status} />
              <StatusBadge value={inspectEvent.verification_status} />
            </div>

            <Button
              size="sm"
              variant="outline"
              className="w-full justify-between"
              onClick={() => {
                const cid = inspectEvent.correlation_id;
                setInspectEvent(null);
                setTimelineCid(cid);
              }}
            >
              <span>Inspect Chronological Timeline ({shortenId(inspectEvent.correlation_id)})</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </Button>

            <pre className="overflow-auto rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] dark:border-slate-800 dark:bg-obsidian-950">
              {JSON.stringify(redactSensitivePayload(inspectEvent), null, 2)}
            </pre>
          </div>
        )}
      </Drawer>
    </div>
  );
}
