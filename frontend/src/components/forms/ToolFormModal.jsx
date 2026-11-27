import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { toolCreateSchema, toolUpdateSchema } from '../../utils/validators';
import { useRegisterToolMutation, useUpdateToolMutation } from '../../hooks/useTools';
import { useToast } from '../../context/ToastContext';
import { Modal } from '../ui/Modal';
import { Input, Textarea } from '../ui/Input';
import { Select } from '../ui/Select';
import { Button } from '../ui/Button';

export function ToolFormModal({ open, onClose, initialTool = null }) {
  const isEdit = Boolean(initialTool);
  const toast = useToast();
  const registerMutation = useRegisterToolMutation();
  const updateMutation = useUpdateToolMutation();
  const activeMutation = isEdit ? updateMutation : registerMutation;

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(isEdit ? toolUpdateSchema : toolCreateSchema),
    defaultValues: {
      name: '',
      description: '',
      category: '',
      risk_level: 'medium',
      enabled: true,
    },
  });

  useEffect(() => {
    if (open) {
      reset(
        initialTool
          ? {
              name: initialTool.name,
              description: initialTool.description,
              category: initialTool.category,
              risk_level: initialTool.risk_level,
              enabled: Boolean(initialTool.enabled),
            }
          : {
              name: '',
              description: '',
              category: 'filesystem',
              risk_level: 'medium',
              enabled: true,
            }
      );
      registerMutation.reset();
      updateMutation.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, initialTool]);

  const onSubmit = async (values) => {
    try {
      if (isEdit) {
        await updateMutation.mutateAsync({
          toolName: initialTool.name,
          payload: values,
        });
        toast.success('Tool updated', `Updated configuration for "${initialTool.name}".`);
      } else {
        const created = await registerMutation.mutateAsync(values);
        toast.success('Tool registered', `Tool "${created.name}" added to registry.`);
      }
      onClose();
    } catch (err) {
      toast.error(isEdit ? 'Failed to update tool' : 'Failed to register tool', err.message);
    }
  };

  return (
    <Modal
      open={open}
      onClose={activeMutation.isPending ? undefined : onClose}
      title={isEdit ? `Edit Tool: ${initialTool.name}` : 'Register Tool Definition'}
      description={
        isEdit
          ? 'Update metadata, risk classification, or availability for this registered tool.'
          : 'Register a tool in the Chaperone Tool Registry. Tools without a backend adapter run in policy-evaluation mode only.'
      }
      preventBackdropClose={activeMutation.isPending}
      footer={
        <>
          <Button variant="outline" onClick={onClose} disabled={activeMutation.isPending}>
            Cancel
          </Button>
          <Button type="submit" form="tool-form" isLoading={activeMutation.isPending}>
            {isEdit ? 'Save Changes' : 'Register Tool'}
          </Button>
        </>
      }
    >
      <form id="tool-form" onSubmit={handleSubmit(onSubmit)} className="space-y-4">
        {!isEdit ? (
          <Input
            label="Tool Name"
            mono
            placeholder="e.g. file_tool or analytics_query"
            hint="Lowercase identifier (letters, digits, '.', '_', '-')"
            error={errors.name?.message}
            {...register('name')}
          />
        ) : (
          <Input label="Tool Name (immutable)" mono value={initialTool.name} disabled />
        )}

        <div className="grid gap-4 sm:grid-cols-2">
          <Input
            label="Category"
            mono
            placeholder="filesystem | communication | database"
            error={errors.category?.message}
            {...register('category')}
          />
          <Select label="Risk Level" error={errors.risk_level?.message} {...register('risk_level')}>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </Select>
        </div>

        <Textarea
          label="Description"
          placeholder="Capabilities, constraints, and security boundaries"
          error={errors.description?.message}
          {...register('description')}
        />

        <label className="flex cursor-pointer items-center gap-2.5 rounded-md border border-slate-200 p-3 text-xs text-slate-700 dark:border-slate-800 dark:text-slate-300">
          <input
            type="checkbox"
            className="h-4 w-4 rounded border-slate-300 text-sky-600 focus:ring-sky-500 dark:border-slate-700 dark:bg-obsidian-950"
            {...register('enabled')}
          />
          <span>Enabled for policy evaluation and gateway execution</span>
        </label>

        {activeMutation.isError && (
          <p className="rounded border border-rose-300 bg-rose-50 px-3 py-2 text-xs text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300" role="alert">
            {activeMutation.error?.message}
          </p>
        )}
      </form>
    </Modal>
  );
}
