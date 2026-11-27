import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Clock,
  HelpCircle,
  Lock,
  MinusCircle,
  PlayCircle,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import { Badge } from './Badge';

const STATUS_CONFIG = {
  // Policy decisions
  allow: { tone: 'success', label: 'ALLOW', Icon: ShieldCheck },
  deny: { tone: 'danger', label: 'DENY', Icon: ShieldAlert },
  require_approval: { tone: 'warning', label: 'REQUIRE APPROVAL', Icon: Clock },

  // Agent statuses
  active: { tone: 'success', label: 'ACTIVE', Icon: CheckCircle2 },
  disabled: { tone: 'neutral', label: 'DISABLED', Icon: Ban },

  // Tool enabled state
  enabled: { tone: 'success', label: 'ENABLED', Icon: CheckCircle2 },

  // Risk levels
  low: { tone: 'info', label: 'LOW RISK', Icon: ShieldCheck },
  medium: { tone: 'warning', label: 'MEDIUM RISK', Icon: AlertTriangle },
  high: { tone: 'danger', label: 'HIGH RISK', Icon: ShieldAlert },
  critical: { tone: 'critical', label: 'CRITICAL RISK', Icon: ShieldAlert },

  // Approval / Execution / Verification states
  pending: { tone: 'warning', label: 'PENDING', Icon: Clock },
  pending_approval: { tone: 'warning', label: 'PENDING APPROVAL', Icon: Clock },
  approved: { tone: 'info', label: 'APPROVED', Icon: CheckCircle2 },
  executed: { tone: 'success', label: 'EXECUTED', Icon: CheckCircle2 },
  rejected: { tone: 'danger', label: 'REJECTED', Icon: XCircle },
  expired: { tone: 'neutral', label: 'EXPIRED', Icon: MinusCircle },
  failed: { tone: 'danger', label: 'FAILED', Icon: XCircle },
  blocked: { tone: 'danger', label: 'BLOCKED', Icon: Ban },
  started: { tone: 'info', label: 'STARTED', Icon: PlayCircle },
  not_executed: { tone: 'neutral', label: 'NOT EXECUTED', Icon: MinusCircle },

  // Verification specifics
  verified: { tone: 'success', label: 'VERIFIED', Icon: ShieldCheck },
  inconclusive: { tone: 'warning', label: 'INCONCLUSIVE', Icon: HelpCircle },
  not_applicable: { tone: 'neutral', label: 'N/A', Icon: MinusCircle },
  unauthenticated: { tone: 'danger', label: 'UNAUTHENTICATED', Icon: Lock },
  invalid_credentials: { tone: 'danger', label: 'INVALID CREDENTIALS', Icon: Lock },
  agent_disabled: { tone: 'danger', label: 'AGENT DISABLED', Icon: Ban },
  tool_unavailable: { tone: 'warning', label: 'TOOL UNAVAILABLE', Icon: AlertTriangle },
  validation_failed: { tone: 'danger', label: 'VALIDATION FAILED', Icon: ShieldAlert },
};

export function StatusBadge({ value, labelOverride, className }) {
  const key = String(value ?? '').trim().toLowerCase();
  const cfg = STATUS_CONFIG[key] || {
    tone: 'neutral',
    label: String(value || 'UNKNOWN').toUpperCase(),
    Icon: HelpCircle,
  };
  const Icon = cfg.Icon;

  return (
    <Badge tone={cfg.tone} className={className}>
      <Icon className="h-3 w-3 shrink-0" aria-hidden="true" />
      <span>{labelOverride || cfg.label}</span>
    </Badge>
  );
}
