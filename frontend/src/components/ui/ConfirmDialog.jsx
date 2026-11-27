import { AlertTriangle } from 'lucide-react';
import { Modal } from './Modal';
import { Button } from './Button';

export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  variant = 'danger',
  isLoading = false,
  details = null,
}) {
  return (
    <Modal
      open={open}
      onClose={isLoading ? undefined : onClose}
      title={title}
      size="sm"
      preventBackdropClose={isLoading}
      footer={
        <>
          <Button variant="outline" onClick={onClose} disabled={isLoading}>
            {cancelLabel}
          </Button>
          <Button variant={variant} onClick={onConfirm} isLoading={isLoading}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="flex gap-3">
        <div
          className={
            variant === 'danger'
              ? 'mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-rose-100 text-rose-600 dark:bg-rose-500/15 dark:text-rose-400'
              : variant === 'success'
                ? 'mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-emerald-100 text-emerald-600 dark:bg-emerald-500/15 dark:text-emerald-400'
                : 'mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-amber-100 text-amber-600 dark:bg-amber-500/15 dark:text-amber-400'
          }
        >
          <AlertTriangle className="h-4 w-4" aria-hidden="true" />
        </div>
        <div className="space-y-2 text-sm text-slate-600 dark:text-slate-300">
          <p>{message}</p>
          {details}
        </div>
      </div>
    </Modal>
  );
}
