import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Bot, Eye, Plus, Power, Search } from 'lucide-react';
import { useAgentsQuery, useUpdateAgentStatusMutation } from '../hooks/useAgents';
import { useToast } from '../context/ToastContext';
import { formatDateTime, shortenId } from '../utils/formatters';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { Pagination } from '../components/ui/Pagination';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { CopyButton } from '../components/ui/CopyButton';
import { DataTable } from '../components/tables/DataTable';
import { AgentFormModal } from '../components/forms/AgentFormModal';
import { ApiKeyRevealModal } from '../components/forms/ApiKeyRevealModal';

export function Agents() {
  const [searchParams, setSearchParams] = useSearchParams();
  const toast = useToast();

  const initialStatus = searchParams.get('status') || '';
  const [statusFilter, setStatusFilter] = useState(initialStatus);
  const [searchTerm, setSearchTerm] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 20;

  const [createOpen, setCreateOpen] = useState(false);
  const [issuedSecret, setIssuedSecret] = useState(null);
  const [toggleTarget, setToggleTarget] = useState(null);

  const agentsQuery = useAgentsQuery({
    page,
    page_size: pageSize,
    status: statusFilter || undefined,
  });
  const statusMutation = useUpdateAgentStatusMutation();

  const items = agentsQuery.data?.items || [];
  const filteredItems = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (agent) =>
        agent.name.toLowerCase().includes(q) ||
        (agent.description || '').toLowerCase().includes(q) ||
        agent.key_prefix.toLowerCase().includes(q) ||
        agent.id.toLowerCase().includes(q)
    );
  }, [items, searchTerm]);

  const handleStatusChange = (val) => {
    setStatusFilter(val);
    setPage(1);
    if (val) {
      setSearchParams({ status: val });
    } else {
      setSearchParams({});
    }
  };

  const handleConfirmToggle = async () => {
    if (!toggleTarget) return;
    const nextStatus = toggleTarget.status === 'active' ? 'disabled' : 'active';
    try {
      await statusMutation.mutateAsync({ agentId: toggleTarget.id, status: nextStatus });
      toast.success(
        nextStatus === 'active' ? 'Agent enabled' : 'Agent disabled',
        `Agent "${toggleTarget.name}" is now ${nextStatus}.`
      );
      setToggleTarget(null);
    } catch (err) {
      toast.error('Status update failed', err.message);
    }
  };

  const columns = [
    {
      key: 'name',
      header: 'Agent',
      render: (agent) => (
        <div className="min-w-[180px]">
          <Link
            to={`/agents/${agent.id}`}
            className="font-medium text-slate-900 hover:text-sky-600 dark:text-slate-100 dark:hover:text-sky-400"
          >
            {agent.name}
          </Link>
          {agent.description && (
            <p className="mt-0.5 line-clamp-1 text-[11px] text-slate-500 dark:text-slate-400">
              {agent.description}
            </p>
          )}
        </div>
      ),
    },
    {
      key: 'id',
      header: 'Agent ID',
      render: (agent) => (
        <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-600 dark:text-slate-400">
          <span title={agent.id}>{shortenId(agent.id)}</span>
          <CopyButton value={agent.id} label="Agent ID" iconOnly />
        </div>
      ),
    },
    {
      key: 'key_prefix',
      header: 'Key Prefix',
      render: (agent) => (
        <code className="rounded bg-slate-100 px-2 py-0.5 font-mono text-[11px] text-slate-700 dark:bg-obsidian-800 dark:text-slate-300">
          {agent.key_prefix}
        </code>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (agent) => <StatusBadge value={agent.status} />,
    },
    {
      key: 'created_at',
      header: 'Created',
      render: (agent) => (
        <span className="whitespace-nowrap tabular-nums text-[11px] text-slate-500 dark:text-slate-400">
          {formatDateTime(agent.created_at)}
        </span>
      ),
    },
    {
      key: 'actions',
      header: 'Actions',
      headerClassName: 'text-right',
      cellClassName: 'text-right',
      render: (agent) => (
        <div className="flex items-center justify-end gap-2">
          <Link to={`/agents/${agent.id}`}>
            <Button variant="ghost" size="xs">
              <Eye className="h-3.5 w-3.5" />
              Details
            </Button>
          </Link>
          <Button
            variant="outline"
            size="xs"
            onClick={() => setToggleTarget(agent)}
          >
            <Power className="h-3.5 w-3.5" />
            {agent.status === 'active' ? 'Disable' : 'Enable'}
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Manage AI agent identities and credential prefixes. Raw API keys are hashed server-side and shown only once upon registration.
        </p>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="h-4 w-4" />
          Register Agent
        </Button>
      </div>

      <Card>
        <div className="flex flex-col gap-3 border-b border-slate-200 p-4 dark:border-slate-800/80 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative w-full sm:max-w-xs">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
            <input
              type="search"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search name, ID, or key prefix..."
              aria-label="Search agents"
              className="w-full rounded-md border border-slate-300 bg-white py-1.5 pl-8 pr-3 text-xs text-slate-900 placeholder:text-slate-400 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
            />
          </div>

          <div className="flex items-center gap-2">
            <label htmlFor="agent-status-filter" className="text-xs text-slate-500 dark:text-slate-400">
              Status:
            </label>
            <select
              id="agent-status-filter"
              value={statusFilter}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
            >
              <option value="">All Statuses</option>
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
            </select>
          </div>
        </div>

        <DataTable
          columns={columns}
          rows={filteredItems}
          isLoading={agentsQuery.isLoading}
          error={agentsQuery.error}
          onRetry={() => agentsQuery.refetch()}
          emptyIcon={Bot}
          emptyTitle={searchTerm || statusFilter ? 'No matching agents' : 'No agents registered yet'}
          emptyDescription={
            searchTerm || statusFilter
              ? 'Try clearing your search or status filter.'
              : 'Register your first AI agent to issue a scoped gateway API key.'
          }
          emptyAction={
            !searchTerm && !statusFilter ? (
              <Button size="sm" onClick={() => setCreateOpen(true)}>
                <Plus className="h-3.5 w-3.5" />
                Register Agent
              </Button>
            ) : null
          }
        />

        <Pagination
          page={page}
          pageSize={pageSize}
          total={agentsQuery.data?.total || 0}
          totalPages={agentsQuery.data?.total_pages || 0}
          onPageChange={setPage}
        />
      </Card>

      <AgentFormModal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={(created) => {
          setIssuedSecret({
            agentName: created.name,
            keyPrefix: created.key_prefix,
            apiKey: created.api_key,
          });
        }}
      />

      <ApiKeyRevealModal
        open={Boolean(issuedSecret)}
        agentName={issuedSecret?.agentName}
        keyPrefix={issuedSecret?.keyPrefix}
        apiKey={issuedSecret?.apiKey}
        onClose={() => setIssuedSecret(null)}
      />

      <ConfirmDialog
        open={Boolean(toggleTarget)}
        onClose={() => setToggleTarget(null)}
        onConfirm={handleConfirmToggle}
        isLoading={statusMutation.isPending}
        variant={toggleTarget?.status === 'active' ? 'danger' : 'success'}
        title={toggleTarget?.status === 'active' ? 'Disable Agent?' : 'Enable Agent?'}
        confirmLabel={toggleTarget?.status === 'active' ? 'Disable Agent' : 'Enable Agent'}
        message={
          toggleTarget?.status === 'active'
            ? `Disabling "${toggleTarget?.name}" immediately blocks all future gateway and MCP tool requests authenticated with its key.`
            : `Re-enabling "${toggleTarget?.name}" restores its ability to evaluate and execute permitted tool calls.`
        }
      />
    </div>
  );
}
