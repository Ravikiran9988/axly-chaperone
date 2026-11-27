import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  Edit3,
  Info,
  Plus,
  Power,
  Search,
  ShieldCheck,
} from 'lucide-react';
import { usePoliciesQuery, useUpdatePolicyMutation } from '../hooks/usePolicies';
import { useAgentsQuery } from '../hooks/useAgents';
import { useToolsQuery } from '../hooks/useTools';
import { useToast } from '../context/ToastContext';
import { detectBroadPolicyRisks } from '../utils/validators';
import { formatDateTime } from '../utils/formatters';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { Pagination } from '../components/ui/Pagination';
import { Drawer } from '../components/ui/Drawer';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { DataTable } from '../components/tables/DataTable';
import { PolicyFormModal } from '../components/forms/PolicyFormModal';

export function Policies() {
  const toast = useToast();
  const [searchTerm, setSearchTerm] = useState('');
  const [agentFilter, setAgentFilter] = useState('');
  const [toolFilter, setToolFilter] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('');
  const [enabledFilter, setEnabledFilter] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 20;

  const [formModalOpen, setFormModalOpen] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState(null);
  const [detailPolicy, setDetailPolicy] = useState(null);
  const [togglePolicy, setTogglePolicy] = useState(null);

  const agentsQuery = useAgentsQuery({ page: 1, page_size: 100 });
  const toolsQuery = useToolsQuery({ page: 1, page_size: 100 });
  const policiesQuery = usePoliciesQuery({
    page,
    page_size: pageSize,
    agent_id: agentFilter || undefined,
    tool_name: toolFilter || undefined,
    decision: decisionFilter || undefined,
    enabled: enabledFilter === '' ? undefined : enabledFilter === 'true',
  });
  const updateMutation = useUpdatePolicyMutation();

  const agents = agentsQuery.data?.items || [];
  const tools = toolsQuery.data?.items || [];
  const agentMap = useMemo(() => new Map(agents.map((a) => [a.id, a])), [agents]);

  const items = policiesQuery.data?.items || [];
  const filteredItems = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.tool_name.toLowerCase().includes(q) ||
        p.action.toLowerCase().includes(q) ||
        p.resource_scope.toLowerCase().includes(q) ||
        (p.description || '').toLowerCase().includes(q)
    );
  }, [items, searchTerm]);

  const handleConfirmToggle = async () => {
    if (!togglePolicy) return;
    const nextEnabled = !togglePolicy.enabled;
    try {
      const updated = await updateMutation.mutateAsync({
        policyId: togglePolicy.id,
        payload: { enabled: nextEnabled },
      });
      toast.success(
        nextEnabled ? 'Policy enabled' : 'Policy disabled',
        `Policy "${updated.name}" updated to v${updated.version}.`
      );
      setTogglePolicy(null);
    } catch (err) {
      toast.error('Failed to update policy', err.message);
    }
  };

  const columns = [
    {
      key: 'name',
      header: 'Policy',
      render: (policy) => {
        const risks = detectBroadPolicyRisks(policy);
        return (
          <div className="min-w-[180px]">
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => setDetailPolicy(policy)}
                className="text-left font-medium text-slate-900 hover:text-sky-600 dark:text-slate-100 dark:hover:text-sky-400"
              >
                {policy.name}
              </button>
              {risks.length > 0 && (
                <span
                  title={risks.join(' ')}
                  className="inline-flex items-center gap-0.5 rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-300"
                >
                  <AlertTriangle className="h-3 w-3" />
                  Broad
                </span>
              )}
            </div>
            {policy.description && (
              <p className="mt-0.5 line-clamp-1 text-[11px] text-slate-500 dark:text-slate-400">
                {policy.description}
              </p>
            )}
          </div>
        );
      },
    },
    {
      key: 'agent',
      header: 'Agent Scope',
      render: (policy) => {
        if (!policy.agent_id) {
          return (
            <span className="rounded border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-medium text-slate-600 dark:border-slate-700 dark:bg-obsidian-800 dark:text-slate-300">
              Global (All Agents)
            </span>
          );
        }
        const ag = agentMap.get(policy.agent_id);
        return (
          <span className="font-mono text-[11px] text-slate-800 dark:text-slate-200">
            {ag?.name || policy.agent_id}
          </span>
        );
      },
    },
    {
      key: 'target',
      header: 'Tool · Action · Resource',
      render: (policy) => (
        <div className="space-y-0.5 font-mono text-[11px]">
          <div className="text-slate-900 dark:text-slate-100">
            {policy.tool_name} · <span className="text-sky-600 dark:text-sky-400">{policy.action}</span>
          </div>
          <div className="text-slate-500 dark:text-slate-400">{policy.resource_scope}</div>
        </div>
      ),
    },
    {
      key: 'decision',
      header: 'Decision',
      render: (policy) => <StatusBadge value={policy.decision} />,
    },
    {
      key: 'priority',
      header: 'Priority / Ver',
      render: (policy) => (
        <div className="tabular-nums text-[11px]">
          <span className="font-semibold text-slate-900 dark:text-slate-100">{policy.priority}</span>
          <span className="ml-1.5 text-slate-500 dark:text-slate-400">v{policy.version}</span>
        </div>
      ),
    },
    {
      key: 'enabled',
      header: 'State',
      render: (policy) => <StatusBadge value={policy.enabled ? 'enabled' : 'disabled'} />,
    },
    {
      key: 'actions',
      header: 'Actions',
      headerClassName: 'text-right',
      cellClassName: 'text-right',
      render: (policy) => (
        <div className="flex items-center justify-end gap-1.5">
          <Button
            variant="ghost"
            size="xs"
            onClick={() => {
              setEditingPolicy(policy);
              setFormModalOpen(true);
            }}
          >
            <Edit3 className="h-3.5 w-3.5" />
            Edit
          </Button>
          <Button variant="outline" size="xs" onClick={() => setTogglePolicy(policy)}>
            <Power className="h-3.5 w-3.5" />
            {policy.enabled ? 'Disable' : 'Enable'}
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Deterministic policy engine rules. Policies are versioned and disabled rather than deleted to preserve audit traceability.
        </p>
        <Button
          onClick={() => {
            setEditingPolicy(null);
            setFormModalOpen(true);
          }}
        >
          <Plus className="h-4 w-4" />
          Create Policy
        </Button>
      </div>

      {/* Policy precedence reminder */}
      <div className="flex items-start gap-3 rounded-lg border border-slate-200 bg-white p-3.5 text-xs text-slate-600 dark:border-slate-800/80 dark:bg-obsidian-900 dark:text-slate-300">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-500" />
        <div>
          <span className="font-semibold text-slate-900 dark:text-slate-100">
            Evaluation Precedence:
          </span>{' '}
          Default <strong>DENY</strong> when zero policies match. Any matching{' '}
          <strong>DENY</strong> rule hard-blocks regardless of numeric priority — human approvals
          can never override an explicit DENY. Between <strong>ALLOW</strong> and{' '}
          <strong>REQUIRE_APPROVAL</strong>, highest priority wins (ties favor{' '}
          <strong>REQUIRE_APPROVAL</strong>).
        </div>
      </div>

      <Card>
        <div className="flex flex-col gap-3 border-b border-slate-200 p-4 dark:border-slate-800/80 xl:flex-row xl:items-center xl:justify-between">
          <div className="relative w-full xl:max-w-xs">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
            <input
              type="search"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search name, action, or resource scope..."
              aria-label="Search policies"
              className="w-full rounded-md border border-slate-300 bg-white py-1.5 pl-8 pr-3 text-xs text-slate-900 placeholder:text-slate-400 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
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
              {agents.map((a) => (
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
              {tools.map((t) => (
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

            <select
              aria-label="Filter by policy state"
              value={enabledFilter}
              onChange={(e) => {
                setEnabledFilter(e.target.value);
                setPage(1);
              }}
              className="rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
            >
              <option value="">All States</option>
              <option value="true">Enabled</option>
              <option value="false">Disabled</option>
            </select>
          </div>
        </div>

        <DataTable
          columns={columns}
          rows={filteredItems}
          isLoading={policiesQuery.isLoading}
          error={policiesQuery.error}
          onRetry={() => policiesQuery.refetch()}
          emptyIcon={ShieldCheck}
          emptyTitle="No policies found"
          emptyDescription="Create deterministic ALLOW, DENY, or REQUIRE_APPROVAL rules for registered tools."
          emptyAction={
            <Button
              size="sm"
              onClick={() => {
                setEditingPolicy(null);
                setFormModalOpen(true);
              }}
            >
              <Plus className="h-3.5 w-3.5" />
              Create Policy
            </Button>
          }
        />

        <Pagination
          page={page}
          pageSize={pageSize}
          total={policiesQuery.data?.total || 0}
          totalPages={policiesQuery.data?.total_pages || 0}
          onPageChange={setPage}
        />
      </Card>

      <PolicyFormModal
        open={formModalOpen}
        onClose={() => {
          setFormModalOpen(false);
          setEditingPolicy(null);
        }}
        initialPolicy={editingPolicy}
        agents={agents}
        tools={tools}
      />

      <Drawer
        open={Boolean(detailPolicy)}
        onClose={() => setDetailPolicy(null)}
        title={detailPolicy?.name || ''}
        subtitle={detailPolicy ? `Version v${detailPolicy.version} · Priority ${detailPolicy.priority}` : ''}
      >
        {detailPolicy && (
          <div className="space-y-4 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge value={detailPolicy.decision} />
              <StatusBadge value={detailPolicy.enabled ? 'enabled' : 'disabled'} />
            </div>

            {detectBroadPolicyRisks(detailPolicy).length > 0 && (
              <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200">
                <p className="font-semibold">Broad Permission Scope</p>
                <ul className="mt-1 list-disc space-y-0.5 pl-4">
                  {detectBroadPolicyRisks(detailPolicy).map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="grid gap-4 rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-obsidian-950 sm:grid-cols-2">
              <div>
                <span className="text-slate-500 dark:text-slate-400">Agent Association</span>
                <p className="mt-0.5 font-mono">
                  {detailPolicy.agent_id
                    ? agentMap.get(detailPolicy.agent_id)?.name || detailPolicy.agent_id
                    : 'Global (All Agents)'}
                </p>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400">Tool</span>
                <p className="mt-0.5 font-mono">{detailPolicy.tool_name}</p>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400">Action Scope</span>
                <p className="mt-0.5 font-mono">{detailPolicy.action}</p>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400">Resource Scope</span>
                <p className="mt-0.5 font-mono">{detailPolicy.resource_scope}</p>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400">Created</span>
                <p className="mt-0.5 tabular-nums">{formatDateTime(detailPolicy.created_at)}</p>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400">Last Updated</span>
                <p className="mt-0.5 tabular-nums">{formatDateTime(detailPolicy.updated_at)}</p>
              </div>
            </div>

            <div>
              <h4 className="font-semibold text-slate-900 dark:text-slate-100">Decision Reason / Notes</h4>
              <p className="mt-1 text-slate-600 dark:text-slate-300">
                {detailPolicy.description || 'No rationale recorded.'}
              </p>
            </div>
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={Boolean(togglePolicy)}
        onClose={() => setTogglePolicy(null)}
        onConfirm={handleConfirmToggle}
        isLoading={updateMutation.isPending}
        variant={togglePolicy?.enabled ? 'danger' : 'success'}
        title={togglePolicy?.enabled ? 'Disable Policy?' : 'Enable Policy?'}
        confirmLabel={togglePolicy?.enabled ? 'Disable Policy' : 'Enable Policy'}
        message={
          togglePolicy?.enabled
            ? `Disabling "${togglePolicy?.name}" removes it from policy evaluation and increments its version to v${(togglePolicy?.version || 1) + 1}.`
            : `Enabling "${togglePolicy?.name}" activates it immediately in the PolicyEngine.`
        }
      />
    </div>
  );
}
