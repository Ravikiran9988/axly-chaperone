import { useEffect, useState } from 'react';
import { AlertTriangle, KeyRound, ShieldCheck } from 'lucide-react';
import { Modal } from '../ui/Modal';
import { Button } from '../ui/Button';
import { CopyButton } from '../ui/CopyButton';

export function ApiKeyRevealModal({ open, agentName, keyPrefix, apiKey, onClose }) {
  const [acknowledged, setAcknowledged] = useState(false);

  useEffect(() => {
    if (open) {
      setAcknowledged(false);
    }
  }, [open]);

  if (!open || !apiKey) return null;

  return (
    <Modal
      open={open}
      onClose={acknowledged ? onClose : undefined}
      title="Agent API Key Issued"
      description={`One-time credential for "${agentName}"`}
      size="md"
      preventBackdropClose
      hideCloseButton
      footer={
        <Button onClick={onClose} disabled={!acknowledged}>
          <ShieldCheck className="h-4 w-4" />
          I Have Saved This Key
        </Button>
      }
    >
      <div className="space-y-4">
        <div
          role="alert"
          className="flex items-start gap-3 rounded-md border border-amber-300 bg-amber-50 p-3.5 text-xs text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
          <div className="space-y-1">
            <p className="font-semibold">Save this API key immediately — it cannot be retrieved again.</p>
            <p className="text-amber-800/90 dark:text-amber-200/80">
              AXLY Chaperone hashes agent keys with PBKDF2-HMAC-SHA256 before persistence and never
              stores this credential in browser storage.
            </p>
          </div>
        </div>

        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span className="flex items-center gap-1.5 font-medium">
              <KeyRound className="h-3.5 w-3.5" />
              X-Agent-Key Secret
            </span>
            {keyPrefix && <span className="font-mono text-[11px]">Prefix: {keyPrefix}</span>}
          </div>
          <div className="flex items-center justify-between gap-2 rounded-md border border-slate-300 bg-slate-50 p-3 dark:border-slate-700 dark:bg-obsidian-950">
            <code className="break-all font-mono text-xs text-emerald-700 dark:text-emerald-300">
              {apiKey}
            </code>
            <CopyButton value={apiKey} label="Copy Key" className="shrink-0" />
          </div>
        </div>

        <label className="flex cursor-pointer items-center gap-2.5 rounded-md border border-slate-200 p-3 text-xs text-slate-700 dark:border-slate-800 dark:text-slate-300">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
            className="h-4 w-4 rounded border-slate-300 text-sky-600 focus:ring-sky-500 dark:border-slate-700 dark:bg-obsidian-950"
          />
          <span>I confirm I have copied this API key to a secure secret manager.</span>
        </label>
      </div>
    </Modal>
  );
}
