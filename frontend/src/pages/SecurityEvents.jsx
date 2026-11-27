import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Filter, Search, ShieldAlert } from 'lucide-react';
import { useAuditEventsQuery } from '../hooks/useAuditEvents';
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
import { DataTable } from '../components/tables/DataTable';

const PRESET_TABS = [
  { id: 'signals', label: 'All Security Signals' },
  { id: 'denied', label: 'Denied & Blocked', decision: 'deny' },
  { id: 'auth', label: 'Unauthorized / Auth', event_type: 'authentication' },
  { id: 'approvals', label: 'Approval Required', decision: 'require_approval' },
  { id: 'exec_fail', label: 'Execution Failures', event_type: 'execution_failed' },
  { id: 'verify_fail', label: 'Verification Failures', verification_status: 'failed' },
];

function isWithinTimeRange(isoString, rangeKey) {
  if (!rangeKey || rangeKey === 'all') return true;
  const ts = new Date(isoString).getTime();
  if (Number.isNaN(ts)) return false;
  const hoursMap = { '1h': 1, '24h': 24, '7d': 24 * 7 };
  const hours = hoursMap[rangeKey];
  if (!hours) return true;
  return Date.now() - ts <= hours * 60 * 60 * 1000;
}

export function SecurityEvents() {
  const [searchParams] = useSearchParams();
  const initialDecision = searchParams.get('decision') || '';
  const initialVerification = searchParams.get('verification_status') || '';

  const [preset, setPreset] = useState(
    initialDecision === 'deny'
      ? 'denied'
      : initialVerification === 'failed'
        ? 'verify_fail'
        : 'signals'
  );
  const [searchTerm, setSearchTerm] = useState('');
  const [correlationLookup, setCorrelationLookup] = useState('');
  const [agentFilter, setAgentFilter] = useState('');
  const [toolFilter, setToolFilter] = useState('');
  const [decisionFilter, setDecisionFilter] = useState(initialDecision);
  const [timeRange, setTimeRange] = useState('all');
  const [page, setPage] = useState(1);
  const pageSize = 25;

  const [selectedEvent, setSelectedEvent] = useState(null);

  const activePreset = PRESET_TABS.find((t) => t.id === preset) || PRESET_TABS[0];

  const eventsQuery = useAuditEventsQuery({
    page,
    page_size: pageSize,
    agent_id: agentFilter || undefined,
    tool_name: toolFilter || undefined,
    decision: decisionFilter || activePreset.decision || undefined,
    event_type: activePreset.event_type || undefined,
    verification_status: activePreset.verification_status || undefined,
    correlation_id: correlationLookup.trim() || undefined,
    order: 'desc',
  });

  const agentsQuery = useAgentsQuery({ page: 1, page_size: 100 });
  const toolsQuery = useToolsQuery({ page: 1, page_size: 100 });
  const agentMap = useMemo(
    () => new Map((agentsQuery.data?.items || []).map((a) => [a.id, a])),
    [agentsQuery.data]
  );

  const filteredItems = useMemo(() => {
    let rows = eventsQuery.data?.items || [];
    if (preset === 'signals' && !decisionFilter) {
      rows = rows.filter(
        (ev) =>
          ev.decision === 'deny' ||
          ev.decision === 'require_approval' ||
          ev.event_type === 'authentication' ||
          ev.event_type === 'execution_failed' ||
          ev.event_type === 'approval_rejected' ||
          ev.event_type === 'approval_expired' ||
          ev.verification_status === 'failed' ||
          ev.verification_status === 'validation_failed'
      );
    }
    if (timeRange !== 'all') {
      rows = rows.filter((ev) => isWithinTimeRange(ev.created_at, timeRange));
    }
    const q = searchTerm.trim().toLowerCase();
    if (q) {
      rows = rows.filter(
        (ev) =>
          ev.tool_name.toLowerCase().includes(q) ||
          ev.action.toLowerCase().includes(q) ||
          ev.resource.toLowerCase().includes(q) ||
          ev.reason.toLowerCase().includes(q) ||
          ev.correlation_id.toLowerCase().includes(q)
      );
    }
    return rows;
  }, [eventsQuery.data, preset, decisionFilter, timeRange, searchTerm]);

  const handlePresetChange = (id) => {
    setPreset(id);
    setDecisionFilter('');
    setPage(1);
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
      key: 'decision',
      header: 'Severity / Decision',
      render: (ev) => (
        <div className="flex flex-wrap items-center gap-1.5">
          <StatusBadge value={ev.decision} />
          <span className="rounded border border-slate-200 px-1.5 py-0.5 font-mono text-[10px] text-slate-600 dark:border-slate-700 dark:text-slate-300">
            {ev.event_type}
          </span>
        </div>
      ),
    },
    {
      key: 'agent',
      header: 'Agent',
      render: (ev) => {
        if (!ev.agent_id) {
          return <span className="font-mono text-[11px] text-rose-500">Unauthenticated</span>;
        }
        const ag = agentMap.get(ev.agent_id);
        return (
          <span className="text-xs font-medium text-slate-800 dark:text-slate-200">
            {ag?.name || shortenId(ev.agent_id)}
          </span>
        );
      },
    },
    {
      key: 'target',
      header: 'Tool · Resource',
      render: (ev) => (
        <div className="max-w-xs">
          <div className="font-mono text-[11px] font-semibold text-slate-900 dark:text-slate-100">
            {ev.tool_name}.{ev.action}
          </div>
          <p className="truncate font-mono text-[11px] text-slate-500 dark:text-slate-400">
            {ev.resource}
          </p>
        </div>
      ),
    },
    {
      key: 'verification',
      header: 'Verification / Exec',
      render: (ev) => (
        <div className="flex flex-wrap gap-1.5">
          <StatusBadge value={ev.verification_status} />
          <StatusBadge value={ev.execution_status} />
        </div>
      ),
    },
    {
      key: 'correlation',
      header: 'Correlation',
      render: (ev) => (
        <span className="font-mono text-[11px] text-sky-600 dark:text-sky-400">
          {shortenId(ev.correlation_id)}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <p className="text-xs text-slate-500 dark:text-slate-400">
        Security signal stream across authentication rejections, policy denials, suspicious validation blocks, human approvals, and verification failures.
      </p>

      {/* Preset Tabs */}
      <div className="flex flex-wrap gap-1.5">
        {PRESET_TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => handlePresetChange(tab.id)}
            className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              preset === tab.id
                ? 'bg-sky-600 text-white dark:bg-sky-500 dark:text-slate-950'
                : 'bg-white text-slate-600 hover:bg-slate-100 dark:bg-obsidian-900 dark:text-slate-400 dark:hover:bg-obsidian-800 dark:hover:text-slate-100'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <Card>
        <div className="space-y-3 border-b border-slate-200 p-4 dark:border-slate-800/80">
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-5">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
              <input
                type="search"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search resource or reason..."
                aria-label="Search security events"
                className="w-full rounded-md border border-slate-300 bg-white py-1.5 pl-8 pr-3 text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
              />
            </div>

            <input
              type="text"
              value={correlationLookup}
              onChange={(e) => {
                setCorrelationLookup(e.target.value);
                setPage(1);
              }}
              placeholder="Exact Correlation ID..."
              aria-label="Correlation ID lookup"
              className="w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
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

            <div className="flex gap-2">
              <select
                aria-label="Filter by decision"
                value={decisionFilter}
                onChange={(e) => {
                  setDecisionFilter(e.target.value);
                  setPage(1);
                }}
                className="w-full rounded-md border border-slate-300 bg-white px-2 py-1.5 text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
              >
                <option value="">Decision: Any</option>
                <option value="deny">DENY</option>
                <option value="require_approval">REQUIRE_APPROVAL</option>
                <option value="allow">ALLOW</option>
              </select>

              <select
                aria-label="Filter by time range"
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="w-full rounded-md border border-slate-300 bg-white px-2 py-1.5 text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
              >
                <option value="all">Time: All</option>
                <option value="1h">Last 1h</option>
                <option value="24h">Last 24h</option>
                <option value="7d">Last 7d</option>
              </select>
            </div>
          </div>

          {timeRange !== 'all' && (
            <p className="flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400">
              <Filter className="h-3 w-3" />
              Time-range filter applies client-side to the fetched page (backend audit API does not yet expose start/end date query parameters).
            </p>
          )}
        </div>

        <DataTable
          columns={columns}
          rows={filteredItems}
          isLoading={eventsQuery.isLoading}
          error={eventsQuery.error}
          onRetry={() => eventsQuery.refetch()}
          onRowClick={(ev) => setSelectedEvent(ev)}
          rowClassName={(ev) =>
            ev.decision === 'deny' || ev.verification_status === 'failed'
              ? 'border-l-4 border-l-rose-500 bg-rose-50/20 dark:bg-rose-500/[0.03]'
              : ev.decision === 'require_approval'
                ? 'border-l-4 border-l-amber-500'
                : 'border-l-4 border-l-emerald-500'
          }
          emptyIcon={ShieldAlert}
          emptyTitle="No matching security events"
          emptyDescription="No security events matched the active filters."
        />

        <Pagination
          page={page}
          pageSize={pageSize}
          total={eventsQuery.data?.total || 0}
          totalPages={eventsQuery.data?.total_pages || 0}
          onPageChange={setPage}
        />
      </Card>

      <Drawer
        open={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        title="Security Event Detail"
        subtitle={selectedEvent ? `Event ${selectedEvent.id}` : ''}
      >
        {selectedEvent && (
          <div className="space-y-4 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge value={selectedEvent.decision} />
              <StatusBadge value={selectedEvent.execution_status} />
              <StatusBadge value={selectedEvent.verification_status} />
            </div>

            <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-obsidian-950">
              <p className="font-semibold text-slate-900 dark:text-slate-100">Reason</p>
              <p className="mt-1 text-slate-700 dark:text-slate-300">{selectedEvent.reason}</p>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <span className="text-slate-500 dark:text-slate-400">Correlation ID</span>
                <div className="mt-0.5 flex items-center gap-1.5 font-mono">
                  <span className="break-all">{selectedEvent.correlation_id}</span>
                  <CopyButton value={selectedEvent.correlation_id} label="CID" iconOnly />
                </div>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400">Timestamp</span>
                <p className="mt-0.5 tabular-nums">{formatDateTime(selectedEvent.created_at)}</p>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400">Tool & Action</span>
                <p className="mt-0.5 font-mono">
                  {selectedEvent.tool_name}.{selectedEvent.action}
                </p>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400">Resource</span>
                <p className="mt-0.5 break-all font-mono">{selectedEvent.resource}</p>
              </div>
            </div>

            {selectedEvent.policy_metadata && (
              <div>
                <h4 className="font-semibold text-slate-900 dark:text-slate-100">Policy Metadata</h4>
                <pre className="mt-1 overflow-auto rounded border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] dark:border-slate-800 dark:bg-obsidian-950">
                  {JSON.stringify(redactSensitivePayload(selectedEvent.policy_metadata), null, 2)}
                </pre>
              </div>
            )}

            {selectedEvent.execution_metadata && (
              <div>
                <h4 className="font-semibold text-slate-900 dark:text-slate-100">
                  Execution Metadata
                </h4>
                <pre className="mt-1 overflow-auto rounded border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] dark:border-slate-800 dark:bg-obsidian-950">
                  {JSON.stringify(redactSensitivePayload(selectedEvent.execution_metadata), null, 2)}
                </pre>
              </div>
            )}

            <div className="pt-2">
              <Link to={`/audit-logs?correlation_id=${encodeURIComponent(selectedEvent.correlation_id)}`}>
                <Button size="sm" className="w-full">
                  Open Full Correlation Timeline in Audit Logs
                </Button>
              </Link>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
