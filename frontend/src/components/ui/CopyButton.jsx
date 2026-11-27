import { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { cn } from '../../utils/cn';

export function CopyButton({ value, label = 'Copy', className, iconOnly = false }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(String(value));
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Fallback for non-secure clipboard contexts
      const textarea = document.createElement('textarea');
      textarea.value = String(value);
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    }
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      title={copied ? 'Copied to clipboard' : `Copy ${label}`}
      aria-label={copied ? 'Copied' : `Copy ${label}`}
      className={cn(
        'inline-flex items-center gap-1 rounded border border-slate-200 bg-slate-50 px-2 py-1 text-xs font-medium text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900 dark:border-slate-700/80 dark:bg-obsidian-800 dark:text-slate-300 dark:hover:bg-obsidian-700 dark:hover:text-slate-100',
        copied && 'border-emerald-500/40 text-emerald-600 dark:text-emerald-400',
        className
      )}
    >
      {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
      {!iconOnly && <span>{copied ? 'Copied' : label}</span>}
    </button>
  );
}
