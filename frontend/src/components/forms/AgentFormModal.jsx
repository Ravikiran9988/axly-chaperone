import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { agentCreateSchema } from '../../utils/validators';
import { useRegisterAgentMutation } from '../../hooks/useAgents';
import { useToast } from '../../context/ToastContext';
import { Modal } from '../ui/Modal';
import { Input, Textarea } from '../ui/Input';
import { Button } from '../ui/Button';

export function AgentFormModal({ open, onClose, onCreated }) {
  const toast = useToast();
  const registerMutation = useRegisterAgentMutation();
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(agentCreateSchema),
    defaultValues: { name: '', description: '' },
  });

  useEffect(() => {
    if (open) {
      reset({ name: '', description: '' });
      registerMutation.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const onSubmit = async (values) => {
    try {
      const created = await registerMutation.mutateAsync(values);
      toast.success('Agent registered', `Agent "${created.name}" is now active.`);
      reset({ name: '', description: '' });
      onClose();
      onCreated?.(created);
    } catch (err) {
      toast.error('Failed to register agent', err.message);
    }
  };

  return (
    <Modal
      open={open}
      onClose={registerMutation.isPending ? undefined : onClose}
      title="Register AI Agent"
      description="Create a new authenticated agent identity. A one-time API key will be issued upon creation."
      preventBackdropClose={registerMutation.isPending}
      footer={
        <>
          <Button variant="outline" onClick={onClose} disabled={registerMutation.isPending}>
            Cancel
          </Button>
          <Button type="submit" form="register-agent-form" isLoading={registerMutation.isPending}>
            Register Agent
          </Button>
        </>
      }
    >
      <form id="register-agent-form" onSubmit={handleSubmit(onSubmit)} className="space-y-4">
        <Input
          label="Agent Name"
          placeholder="e.g. invoice-summary-agent"
          hint="2–128 characters, alphanumeric start/end, allowed: letters, digits, spaces, . _ -"
          error={errors.name?.message}
          {...register('name')}
        />
        <Textarea
          label="Description (optional)"
          placeholder="Purpose, environment, and operational boundaries of this agent"
          error={errors.description?.message}
          {...register('description')}
        />
        {registerMutation.isError && (
          <p className="rounded border border-rose-300 bg-rose-50 px-3 py-2 text-xs text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300" role="alert">
            {registerMutation.error?.message}
          </p>
        )}
      </form>
    </Modal>
  );
}
