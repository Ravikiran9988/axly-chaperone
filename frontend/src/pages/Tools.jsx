import { useMemo, useState } from 'react';
import {
  CheckCircle2,
  Edit3,
  Info,
  Plus,
  Power,
  Search,
  ShieldAlert,
  Wrench,
} from 'lucide-react';
import { useToolsQuery, useUpdateToolMutation } from '../hooks/useTools';
import { usePoliciesQuery } from '../hooks/usePolicies';
import { useToast } from '../context/ToastContext';
import { getToolExecutionCapabilities } from '../utils/toolCapabilities';
import { formatDateTime } from '../utils/formatters';
import { Card, CardContent } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { Pagination } from '../components/ui/Pagination';
import { Drawer } from '../components/ui/Drawer';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { DataTable } from '../components/tables/DataTable';
import { ToolFormModal } from '../components/forms/ToolFormModal';

export function Tools() {
  const toast = useToast();
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [enabledFilter, setEnabledFilter] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 20;

  const [formModalOpen, setFormModalOpen] = useState(false);
  const [editingTool, setEditingTool] = useState(null);
  const [detailTool, setDetailTool] = useState(null);
  const [toggleTool, setToggleTool] = useState(null);

  const toolsQuery = useToolsQuery({
    page,
    page_size: pageSize,
    category: categoryFilter || undefined,
    risk_level: riskFilter || undefined,
    enabled: enabledFilter === '' ? undefined : enabledFilter === 'true',
  });
  const detailPoliciesQuery = usePoliciesQuery(
    { tool_name: detailTool?.name, page: 1, page_size: 20 },
    { enabled: Boolean(detailTool) }
  );
  const updateMutation = useUpdateToolMutation();

  const items = toolsQuery.data?.items || [];
  const filteredItems = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (t) =>
        t.name.toLowerCase().includes(q) ||
        t.category.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q)
    );
  }, [items, searchTerm]);

  const executableCount = items.filter(
    (t) => getToolExecutionCapabilities(t).executionState === 'executable'
  ).length;
  const evalOnlyCount = items.filter(
    (t) => getToolExecutionCapabilities(t).executionState === 'evaluation_only'
  ).length;

  const handleConfirmToggle = async () => {
    if (!toggleTool) return;
    const nextEnabled = !toggleTool.enabled;
    try {
      await updateMutation.mutateAsync({
        toolName: toggleTool.name,
        payload: { enabled: nextEnabled },
      });
      toast.success(
        nextEnabled ? 'Tool enabled' : 'Tool disabled',
        `Tool "${toggleTool.name}" is now ${nextEnabled ? 'enabled' : 'disabled'}.`
      );
      setToggleTool(null);
    } catch (err) {
      toast.error('Failed to update tool', err.message);
    }
  };

  const columns = [
    {
      key: 'name',
      header: 'Tool Name',
      render: (tool) => (
        <div>
          <button
            type="button"
            onClick={() => setDetailTool(tool)}
            className="font-mono text-xs font-semibold text-slate-900 hover:text-sky-600 dark:text-slate-100 dark:hover:text-sky-400"
          >
            {tool.name}
          </button>
          <p className="mt-0.5 line-clamp-1 text-[11px] text-slate-500 dark:text-slate-400">
            {tool.description}
          </p>
        </div>
      ),
    },
    {
      key: 'category',
      header: 'Category',
      render: (tool) => (
        <span className="rounded border border-slate-200 bg-slate-50 px-2 py-0.5 font-mono text-[11px] text-slate-700 dark:border-slate-700 dark:bg-obsidian-800 dark:text-slate-300">
          {tool.category}
        </span>
      ),
    },
    {
      key: 'risk_level',
      header: 'Risk Level',
      render: (tool) => <StatusBadge value={tool.risk_level} />,
    },
    {
      key: 'execution',
      header: 'Execution Mode',
      render: (tool) => {
        const cap = getToolExecutionCapabilities(tool);
        if (cap.executionState === 'executable') {
          return (
            <Badge tone="success">
              <CheckCircle2 className="h-3 w-3" />
              Executable Adapter
            </Badge>
          );
        }
        if (cap.executionState === 'adapter_disabled') {
          return (
            <Badge tone="warning">
              <ShieldAlert className="h-3 w-3" />
              Adapter Disabled
            </Badge>
          );
        }
        return (
          <Badge tone="neutral">
            <Info className="h-3 w-3" />
            Evaluation Only
          </Badge>
        );
      },
    },
    {
      key: 'supported_actions',
      header: 'Supported Actions',
      render: (tool) => {
        const cap = getToolExecutionCapabilities(tool);
        if (!cap.supportedActions.length) {
          return <span className="text-[11px] text-slate-400">No runtime adapter</span>;
        }
        return (
          <div className="flex flex-wrap gap-1">
            {cap.supportedActions.map((act) => (
              <code
                key={act}
                className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-700 dark:bg-obsidian-800 dark:text-slate-300"
              >
                {act}
              </code>
            ))}
          </div>
        );
      },
    },
    {
      key: 'enabled',
      header: 'Status',
      render: (tool) => <StatusBadge value={tool.enabled ? 'enabled' : 'disabled'} />,
    },
    {
      key: 'actions',
      header: 'Actions',
      headerClassName: 'text-right',
      cellClassName: 'text-right',
      render: (tool) => (
        <div className="flex items-center justify-end gap-1.5">
          <Button
            variant="ghost"
            size="xs"
            onClick={() => {
              setEditingTool(tool);
              setFormModalOpen(true);
            }}
          >
            <Edit3 className="h-3.5 w-3.5" />
            Edit
          </Button>
          <Button variant="outline" size="xs" onClick={() => setToggleTool(tool)}>
            <Power className="h-3.5 w-3.5" />
            {tool.enabled ? 'Disable' : 'Enable'}
          </Button>
        </div>
      ),
    },
  ];

  const detailCap = detailTool ? getToolExecutionCapabilities(detailTool) : null;

  return (
    <div className="space-y-5">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Distinguishes tools backed by controlled Phase 2 execution adapters from policy-evaluation-only registry entries.
        </p>
        <Button
          onClick={() => {
            setEditingTool(null);
            setFormModalOpen(true);
          }}
        >
          <Plus className="h-4 w-4" />
          Register Tool
        </Button>
      </div>

      {/* Summary distinction strip */}
      <div className="grid gap-3 sm:grid-cols-3">
        <Card>
          <CardContent className="p-4">
            <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
              Registered in Registry
            </p>
            <p className="mt-1 text-xl font-semibold tabular-nums text-slate-900 dark:text-slate-100">
              {toolsQuery.data?.total ?? 0}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
              Executable Adapters (Active)
            </p>
            <p className="mt-1 text-xl font-semibold tabular-nums text-emerald-600 dark:text-emerald-400">
              {executableCount}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
              Policy-Evaluation Only (Page)
            </p>
            <p className="mt-1 text-xl font-semibold tabular-nums text-slate-700 dark:text-slate-300">
              {evalOnlyCount}
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <div className="flex flex-col gap-3 border-b border-slate-200 p-4 dark:border-slate-800/80 lg:flex-row lg:items-center lg:justify-between">
          <div className="relative w-full lg:max-w-xs">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
            <input
              type="search"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search tools by name or description..."
              aria-label="Search tools"
              className="w-full rounded-md border border-slate-300 bg-white py-1.5 pl-8 pr-3 text-xs text-slate-900 placeholder:text-slate-400 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <input
              type="text"
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setPage(1);
              }}
              placeholder="Category filter..."
              aria-label="Filter by category"
              className="w-36 rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 placeholder:text-slate-400 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
            />
            <select
              aria-label="Filter by risk level"
              value={riskFilter}
              onChange={(e) => {
                setRiskFilter(e.target.value);
                setPage(1);
              }}
              className="rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 focus:border-sky-500 focus:outline-none dark:border-slate-700/80 dark:bg-obsidian-950 dark:text-slate-100"
            >
              <option value="">All Risk Levels</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
            <select
              aria-label="Filter by enabled status"
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
          isLoading={toolsQuery.isLoading}
          error={toolsQuery.error}
          onRetry={() => toolsQuery.refetch()}
          emptyIcon={Wrench}
          emptyTitle="No tools registered"
          emptyDescription="Register a tool definition (e.g. file_tool, email_tool, database_tool) to govern agent access."
        />

        <Pagination
          page={page}
          pageSize={pageSize}
          total={toolsQuery.data?.total || 0}
          totalPages={toolsQuery.data?.total_pages || 0}
          onPageChange={setPage}
        />
      </Card>

      <ToolFormModal
        open={formModalOpen}
        onClose={() => {
          setFormModalOpen(false);
          setEditingTool(null);
        }}
        initialTool={editingTool}
      />

      <Drawer
        open={Boolean(detailTool)}
        onClose={() => setDetailTool(null)}
        title={detailTool?.name || ''}
        subtitle={detailTool ? `${detailTool.category} · ${detailCap?.executionLabel}` : ''}
      >
        {detailTool && detailCap && (
          <div className="space-y-5 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge value={detailTool.enabled ? 'enabled' : 'disabled'} />
              <StatusBadge value={detailTool.risk_level} />
              <Badge tone={detailCap.hasAdapter ? 'success' : 'neutral'}>
                {detailCap.executionLabel}
              </Badge>
            </div>

            <div>
              <h4 className="font-semibold text-slate-900 dark:text-slate-100">Description</h4>
              <p className="mt-1 text-slate-600 dark:text-slate-300">{detailTool.description}</p>
            </div>

            {detailCap.spec ? (
              <div className="space-y-3 rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-obsidian-950">
                <h4 className="font-semibold text-slate-900 dark:text-slate-100">
                  Controlled Adapter Capabilities ({detailCap.spec.adapterClass})
                </h4>
                <div>
                  <span className="text-slate-500 dark:text-slate-400">Supported Actions:</span>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    {detailCap.supportedActions.map((act) => (
                      <code
                        key={act}
                        className="rounded border border-slate-200 bg-white px-2 py-0.5 font-mono text-[11px] dark:border-slate-700 dark:bg-obsidian-900"
                      >
                        {act}
                      </code>
                    ))}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 dark:text-slate-400">Execution Boundary:</span>
                  <p className="mt-0.5 text-slate-700 dark:text-slate-300">
                    {detailCap.spec.runtimeBoundary}
                  </p>
                </div>
                <div>
                  <span className="text-slate-500 dark:text-slate-400">Independent Verification:</span>
                  <p className="mt-0.5 text-slate-700 dark:text-slate-300">
                    {detailCap.spec.verificationMethod}
                  </p>
                </div>
              </div>
            ) : (
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 text-slate-600 dark:border-slate-800 dark:bg-obsidian-950 dark:text-slate-300">
                <p className="font-semibold text-slate-900 dark:text-slate-100">
                  Policy Evaluation Only
                </p>
                <p className="mt-1">
                  No controlled Phase 2 execution adapter is registered in{' '}
                  <code>AdapterRegistry</code> for <code>{detailTool.name}</code>. Requests can be
                  evaluated via <code>/api/v1/gateway/evaluate</code>, while execution dispatch will
                  safely fail closed.
                </p>
              </div>
            )}

            <div className="grid gap-3 border-t border-slate-200 pt-4 dark:border-slate-800 sm:grid-cols-2">
              <div>
                <span className="text-slate-500 dark:text-slate-400">Created At</span>
                <p className="mt-0.5 tabular-nums">{formatDateTime(detailTool.created_at)}</p>
              </div>
              <div>
                <span className="text-slate-500 dark:text-slate-400">Updated At</span>
                <p className="mt-0.5 tabular-nums">{formatDateTime(detailTool.updated_at)}</p>
              </div>
            </div>

            <div className="border-t border-slate-200 pt-4 dark:border-slate-800">
              <h4 className="font-semibold text-slate-900 dark:text-slate-100">
                Policies Referencing {detailTool.name}
              </h4>
              <div className="mt-2 space-y-2">
                {(detailPoliciesQuery.data?.items || []).length === 0 ? (
                  <p className="text-slate-500 dark:text-slate-400">
                    No policies reference this tool yet.
                  </p>
                ) : (
                  detailPoliciesQuery.data.items.map((pol) => (
                    <div
                      key={pol.id}
                      className="flex items-center justify-between rounded border border-slate-200 px-3 py-2 dark:border-slate-800"
                    >
                      <div>
                        <p className="font-medium text-slate-900 dark:text-slate-100">{pol.name}</p>
                        <p className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                          {pol.action} · {pol.resource_scope}
                        </p>
                      </div>
                      <StatusBadge value={pol.decision} />
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={Boolean(toggleTool)}
        onClose={() => setToggleTool(null)}
        onConfirm={handleConfirmToggle}
        isLoading={updateMutation.isPending}
        variant={toggleTool?.enabled ? 'danger' : 'success'}
        title={toggleTool?.enabled ? 'Disable Tool?' : 'Enable Tool?'}
        confirmLabel={toggleTool?.enabled ? 'Disable Tool' : 'Enable Tool'}
        message={
          toggleTool?.enabled
            ? `Disabling "${toggleTool?.name}" causes all gateway evaluation, execution, and pending pre-execution checks for this tool to return DENY.`
            : `Enabling "${toggleTool?.name}" permits policy evaluation and execution according to active policies.`
        }
      />
    </div>
  );
}
