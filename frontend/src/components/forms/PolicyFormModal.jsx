import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { AlertTriangle, ShieldAlert } from 'lucide-react';
import {
  detectBroadPolicyRisks,
  policyCreateSchema,
  policyUpdateSchema,
} from '../../utils/validators';
import { CONTROLLED_ADAPTER_SPECS } from '../../utils/toolCapabilities';
import { useCreatePolicyMutation, useUpdatePolicyMutation } from '../../hooks/usePolicies';
import { useToast } from '../../context/ToastContext';
import { Modal } from '../ui/Modal';
import { Input, Textarea } from '../ui/Input';
import { Select } from '../ui/Select';
import { Button } from '../ui/Button';

export function PolicyFormModal({
  open,
  onClose,
  initialPolicy = null,
  agents = [],
  tools = [],
}) {
  const isEdit = Boolean(initialPolicy);
  const toast = useToast();
  const createMutation = useCreatePolicyMutation();
  const updateMutation = useUpdatePolicyMutation();
  const activeMutation = isEdit ? updateMutation : createMutation;

  const {
    register,
    handleSubmit,
    reset,
    watch,
    setValue,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(isEdit ? policyUpdateSchema : policyCreateSchema),
    defaultValues: {
      name: '',
      description: '',
      agent_id: '',
      tool_name: '',
      action: '',
      resource_scope: '',
      decision: 'require_approval',
      priority: 100,
      enabled: true,
    },
  });

  useEffect(() => {
    if (open) {
      if (initialPolicy) {
        reset({
          description: initialPolicy.description || '',
          action: initialPolicy.action,
          resource_scope: initialPolicy.resource_scope,
          decision: initialPolicy.decision,
          priority: initialPolicy.priority,
          enabled: Boolean(initialPolicy.enabled),
        });
      } else {
        reset({
          name: '',
          description: '',
          agent_id: '',
          tool_name: tools[0]?.name || '',
          action: '',
          resource_scope: '',
          decision: 'require_approval',
          priority: 100,
          enabled: true,
        });
      }
      createMutation.reset();
      updateMutation.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, initialPolicy]);

  const watchedTool = isEdit ? initialPolicy.tool_name : watch('tool_name');
  const watchedAgentId = isEdit ? initialPolicy.agent_id : watch('agent_id');
  const watchedAction = watch('action') || '';
  const watchedScope = watch('resource_scope') || '';
  const watchedDecision = watch('decision');

  const toolSpec = CONTROLLED_ADAPTER_SPECS[(watchedTool || '').toLowerCase()];
  const broadWarnings = detectBroadPolicyRisks({
    agent_id: watchedAgentId || null,
    action: watchedAction.trim().toLowerCase(),
    resource_scope: watchedScope.trim(),
    decision: watchedDecision,
  });

  const onSubmit = async (values) => {
    try {
      if (isEdit) {
        const updated = await updateMutation.mutateAsync({
          policyId: initialPolicy.id,
          payload: values,
        });
        toast.success(
          'Policy updated',
          `Policy "${updated.name}" updated to version v${updated.version}.`
        );
      } else {
        const created = await createMutation.mutateAsync(values);
        toast.success('Policy created', `Policy "${created.name}" is now active in the engine.`);
      }
      onClose();
    } catch (err) {
      toast.error(isEdit ? 'Failed to update policy' : 'Failed to create policy', err.message);
    }
  };

  return (
    <Modal
      open={open}
      onClose={activeMutation.isPending ? undefined : onClose}
      title={isEdit ? `Edit Policy: ${initialPolicy.name}` : 'Create Authorization Policy'}
      description={
        isEdit
          ? `Updating increments policy version (currently v${initialPolicy.version}). Name, agent, and tool are immutable.`
          : 'Define a deterministic authorization rule evaluated by the Chaperone PolicyEngine.'
      }
      size="lg"
      preventBackdropClose={activeMutation.isPending}
      footer={
        <>
          <Button variant="outline" onClick={onClose} disabled={activeMutation.isPending}>
            Cancel
          </Button>
          <Button type="submit" form="policy-form" isLoading={activeMutation.isPending}>
            {isEdit ? 'Save & Increment Version' : 'Create Policy'}
          </Button>
        </>
      }
    >
      <form id="policy-form" onSubmit={handleSubmit(onSubmit)} className="space-y-4">
        {isEdit ? (
          <div className="grid gap-3 rounded-md border border-slate-200 bg-slate-50 p-3 text-xs dark:border-slate-800 dark:bg-obsidian-950 sm:grid-cols-3">
            <div>
              <span className="text-slate-500 dark:text-slate-400">Policy Name</span>
              <p className="mt-0.5 font-medium text-slate-900 dark:text-slate-100">
                {initialPolicy.name}
              </p>
            </div>
            <div>
              <span className="text-slate-500 dark:text-slate-400">Agent Association</span>
              <p className="mt-0.5 font-mono text-slate-900 dark:text-slate-100">
                {initialPolicy.agent_id
                  ? agents.find((a) => a.id === initialPolicy.agent_id)?.name ||
                    initialPolicy.agent_id
                  : 'Global (All Agents)'}
              </p>
            </div>
            <div>
              <span className="text-slate-500 dark:text-slate-400">Target Tool</span>
              <p className="mt-0.5 font-mono text-slate-900 dark:text-slate-100">
                {initialPolicy.tool_name}
              </p>
            </div>
          </div>
        ) : (
          <>
            <Input
              label="Policy Name"
              placeholder="e.g. allow-invoice-read-docs"
              error={errors.name?.message}
              {...register('name')}
            />
            <div className="grid gap-4 sm:grid-cols-2">
              <Select label="Agent Association" error={errors.agent_id?.message} {...register('agent_id')}>
                <option value="">Global — All Agents</option>
                {agents.map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.name} ({agent.status})
                  </option>
                ))}
              </Select>

              <Select label="Registered Tool" error={errors.tool_name?.message} {...register('tool_name')}>
                <option value="">Select a registered tool...</option>
                {tools.map((tool) => (
                  <option key={tool.name} value={tool.name}>
                    {tool.name} ({tool.category})
                  </option>
                ))}
              </Select>
            </div>
          </>
        )}

        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <Input
              label="Action"
              mono
              placeholder="* or read, write, send..."
              error={errors.action?.message}
              {...register('action')}
            />
            {toolSpec && (
              <div className="mt-1.5 flex flex-wrap items-center gap-1">
                <span className="text-[11px] text-slate-500 dark:text-slate-400">Quick fill:</span>
                {[...toolSpec.supportedActions, '*'].map((act) => (
                  <button
                    key={act}
                    type="button"
                    onClick={() => setValue('action', act, { shouldValidate: true })}
                    className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[10px] text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-obsidian-800 dark:text-slate-300 dark:hover:bg-obsidian-700"
                  >
                    {act}
                  </button>
                ))}
              </div>
            )}
          </div>

          <div>
            <Input
              label="Resource Scope"
              mono
              placeholder="documents/*, *@company.com, demo_invoices, or *"
              error={errors.resource_scope?.message}
              {...register('resource_scope')}
            />
            {toolSpec && (
              <div className="mt-1.5 flex flex-wrap items-center gap-1">
                <span className="text-[11px] text-slate-500 dark:text-slate-400">Examples:</span>
                {toolSpec.exampleResources.map((ex) => (
                  <button
                    key={ex}
                    type="button"
                    onClick={() => setValue('resource_scope', ex, { shouldValidate: true })}
                    className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[10px] text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-obsidian-800 dark:text-slate-300 dark:hover:bg-obsidian-700"
                  >
                    {ex}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <Select label="Decision" error={errors.decision?.message} {...register('decision')}>
            <option value="deny">DENY (Hard-block — overrides all other decisions)</option>
            <option value="require_approval">REQUIRE_APPROVAL (Human approval gate)</option>
            <option value="allow">ALLOW (Direct permitted execution)</option>
          </Select>

          <Input
            label="Priority (0 – 10000)"
            type="number"
            min={0}
            max={10000}
            hint="Higher number takes precedence between ALLOW and REQUIRE_APPROVAL"
            error={errors.priority?.message}
            {...register('priority')}
          />
        </div>

        <Textarea
          label="Description / Reason (optional)"
          placeholder="Security rationale for this policy rule"
          rows={2}
          error={errors.description?.message}
          {...register('description')}
        />

        <label className="flex cursor-pointer items-center gap-2.5 rounded-md border border-slate-200 p-3 text-xs text-slate-700 dark:border-slate-800 dark:text-slate-300">
          <input
            type="checkbox"
            className="h-4 w-4 rounded border-slate-300 text-sky-600 focus:ring-sky-500 dark:border-slate-700 dark:bg-obsidian-950"
            {...register('enabled')}
          />
          <span>Policy enabled</span>
        </label>

        {watchedDecision === 'require_approval' && (
          <div className="flex items-start gap-2.5 rounded-md border border-sky-200 bg-sky-50/70 p-3 text-xs text-sky-900 dark:border-sky-500/30 dark:bg-sky-500/10 dark:text-sky-200">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-sky-600 dark:text-sky-400" />
            <p>
              <strong>Precedence guarantee:</strong> Human approval can only authorize{' '}
              <code>REQUIRE_APPROVAL</code> decisions. It can never override an explicit{' '}
              <code>DENY</code> policy at any priority.
            </p>
          </div>
        )}

        {broadWarnings.length > 0 && (
          <div
            role="alert"
            className="flex items-start gap-2.5 rounded-md border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200"
          >
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
            <div className="space-y-1">
              <p className="font-semibold">Broad Permission Warning</p>
              <ul className="list-disc space-y-0.5 pl-4">
                {broadWarnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {activeMutation.isError && (
          <p className="rounded border border-rose-300 bg-rose-50 px-3 py-2 text-xs text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300" role="alert">
            {activeMutation.error?.message}
          </p>
        )}
      </form>
    </Modal>
  );
}
