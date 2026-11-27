import { useQuery } from '@tanstack/react-query';
import { listAgents } from '../services/agents';
import { listTools } from '../services/tools';
import { listApprovals } from '../services/approvals';
import { listAuditEvents } from '../services/audit';

const SECURITY_EVENT_TYPES = new Set([
  'authentication',
  'approval_requested',
  'approval_rejected',
  'approval_expired',
  'execution_failed',
]);

const EXECUTION_EVENT_TYPES = new Set([
  'execution_completed',
  'execution_failed',
  'verification_completed',
]);

function buildTrendBuckets(events) {
  if (!events.length) return [];

  const timestamps = events
    .map((ev) => new Date(ev.created_at).getTime())
    .filter((ts) => !Number.isNaN(ts));
  if (!timestamps.length) return [];

  const minTs = Math.min(...timestamps);
  const maxTs = Math.max(...timestamps);
  const spanHours = (maxTs - minTs) / (1000 * 60 * 60);
  const groupByDay = spanHours > 36;

  const bucketMap = new Map();
  const sorted = [...events].sort(
    (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
  );

  for (const ev of sorted) {
    const dt = new Date(ev.created_at);
    if (Number.isNaN(dt.getTime())) continue;
    const key = groupByDay
      ? dt.toISOString().slice(0, 10)
      : `${dt.toISOString().slice(0, 10)} ${String(dt.getUTCHours()).padStart(2, '0')}:00`;
    const label = groupByDay
      ? new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric' }).format(dt)
      : new Intl.DateTimeFormat('en-US', {
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          hour12: false,
        }).format(dt);

    if (!bucketMap.has(key)) {
      bucketMap.set(key, {
        bucket: label,
        allow: 0,
        deny: 0,
        require_approval: 0,
        total: 0,
      });
    }
    const entry = bucketMap.get(key);
    entry.total += 1;
    if (ev.decision === 'allow') entry.allow += 1;
    else if (ev.decision === 'deny') entry.deny += 1;
    else if (ev.decision === 'require_approval') entry.require_approval += 1;
  }

  return Array.from(bucketMap.values());
}

function buildToolDistribution(events) {
  const byTool = new Map();
  for (const ev of events) {
    const name = ev.tool_name || 'unknown';
    if (!byTool.has(name)) {
      byTool.set(name, { tool: name, allow: 0, deny: 0, require_approval: 0, total: 0 });
    }
    const entry = byTool.get(name);
    entry.total += 1;
    if (ev.decision === 'allow') entry.allow += 1;
    else if (ev.decision === 'deny') entry.deny += 1;
    else if (ev.decision === 'require_approval') entry.require_approval += 1;
  }
  return Array.from(byTool.values()).sort((a, b) => b.total - a.total);
}

/**
 * Aggregates real dashboard metrics strictly from backend endpoints without mock data.
 */
export function useDashboardMetrics({ refetchInterval = 30000 } = {}) {
  return useQuery({
    queryKey: ['dashboard', 'overview'],
    refetchInterval,
    staleTime: 10000,
    queryFn: async () => {
      const [
        agentsAll,
        agentsActive,
        toolsAll,
        toolsEnabled,
        approvalsAll,
        auditRecent,
        auditAllowTotal,
        auditDenyTotal,
        auditApprovalTotal,
        verifiedExecutionsTotal,
        failedVerificationsTotal,
      ] = await Promise.all([
        listAgents({ page: 1, page_size: 100 }),
        listAgents({ page: 1, page_size: 1, status: 'active' }),
        listTools({ page: 1, page_size: 100 }),
        listTools({ page: 1, page_size: 1, enabled: true }),
        listApprovals({ page: 1, page_size: 100 }),
        listAuditEvents({ page: 1, page_size: 100, order: 'desc' }),
        listAuditEvents({ page: 1, page_size: 1, decision: 'allow' }),
        listAuditEvents({ page: 1, page_size: 1, decision: 'deny' }),
        listAuditEvents({ page: 1, page_size: 1, decision: 'require_approval' }),
        listAuditEvents({
          page: 1,
          page_size: 1,
          event_type: 'verification_completed',
          verification_status: 'verified',
        }),
        listAuditEvents({
          page: 1,
          page_size: 1,
          event_type: 'verification_completed',
          verification_status: 'failed',
        }),
      ]);

      const approvalItems = approvalsAll.items || [];
      let pendingApprovalsList = approvalItems.filter((a) => a.status === 'pending');
      let approvalCounts;

      if (approvalsAll.total <= approvalItems.length) {
        approvalCounts = {
          pending: pendingApprovalsList.length,
          approved: approvalItems.filter((a) => a.status === 'approved').length,
          executed: approvalItems.filter((a) => a.status === 'executed').length,
          rejected: approvalItems.filter((a) => a.status === 'rejected').length,
          expired: approvalItems.filter((a) => a.status === 'expired').length,
          failed: approvalItems.filter((a) => a.status === 'failed').length,
        };
      } else {
        const [pPend, pAppr, pExec, pRej, pExp, pFail] = await Promise.all([
          listApprovals({ page: 1, page_size: 10, status: 'pending' }),
          listApprovals({ page: 1, page_size: 1, status: 'approved' }),
          listApprovals({ page: 1, page_size: 1, status: 'executed' }),
          listApprovals({ page: 1, page_size: 1, status: 'rejected' }),
          listApprovals({ page: 1, page_size: 1, status: 'expired' }),
          listApprovals({ page: 1, page_size: 1, status: 'failed' }),
        ]);
        pendingApprovalsList = pPend.items || [];
        approvalCounts = {
          pending: pPend.total,
          approved: pAppr.total,
          executed: pExec.total,
          rejected: pRej.total,
          expired: pExp.total,
          failed: pFail.total,
        };
      }

      const events = auditRecent.items || [];
      const isCompleteAuditHistory = auditRecent.total <= events.length;

      // Group unique gateway requests by correlation_id when full audit history fits in the page
      const uniqueCorrelations = new Map();
      for (const ev of events) {
        if (!ev.correlation_id) continue;
        if (!uniqueCorrelations.has(ev.correlation_id)) {
          uniqueCorrelations.set(ev.correlation_id, new Set());
        }
        uniqueCorrelations.get(ev.correlation_id).add(ev.decision);
      }

      let distinctAllowed = 0;
      let distinctBlocked = 0;
      for (const decisions of uniqueCorrelations.values()) {
        if (decisions.has('deny')) {
          distinctBlocked += 1;
        } else if (decisions.has('allow')) {
          distinctAllowed += 1;
        }
      }

      const decisionBreakdown = [
        { name: 'ALLOW', key: 'allow', count: auditAllowTotal.total },
        { name: 'DENY', key: 'deny', count: auditDenyTotal.total },
        { name: 'REQUIRE_APPROVAL', key: 'require_approval', count: auditApprovalTotal.total },
      ];

      const approvalActivity = [
        { status: 'PENDING', count: approvalCounts.pending },
        { status: 'EXECUTED', count: approvalCounts.executed },
        { status: 'APPROVED', count: approvalCounts.approved },
        { status: 'REJECTED', count: approvalCounts.rejected },
        { status: 'EXPIRED', count: approvalCounts.expired },
        { status: 'FAILED', count: approvalCounts.failed },
      ];

      const agentMap = new Map((agentsAll.items || []).map((a) => [a.id, a]));
      const toolMap = new Map((toolsAll.items || []).map((t) => [t.name, t]));

      const recentSecurityEvents = events
        .filter(
          (ev) =>
            ev.decision === 'deny' ||
            ev.decision === 'require_approval' ||
            ev.verification_status === 'failed' ||
            SECURITY_EVENT_TYPES.has(ev.event_type)
        )
        .slice(0, 8);

      const recentExecutions = events
        .filter((ev) => EXECUTION_EVENT_TYPES.has(ev.event_type))
        .slice(0, 8);

      return {
        metrics: {
          registeredAgents: agentsAll.total,
          activeAgents: agentsActive.total,
          registeredTools: toolsAll.total,
          enabledTools: toolsEnabled.total,
          requestsEvaluated: isCompleteAuditHistory
            ? uniqueCorrelations.size
            : auditRecent.total,
          requestsEvaluatedIsExactFlows: isCompleteAuditHistory,
          allowedRequests: isCompleteAuditHistory ? distinctAllowed : auditAllowTotal.total,
          blockedRequests: isCompleteAuditHistory ? distinctBlocked : auditDenyTotal.total,
          totalAuditEvents: auditRecent.total,
          pendingApprovals: approvalCounts.pending,
          verifiedExecutions: verifiedExecutionsTotal.total,
          failedVerifications: failedVerificationsTotal.total,
        },
        auditWindowInfo: {
          totalEvents: auditRecent.total,
          fetchedEvents: events.length,
          isCompleteHistory: isCompleteAuditHistory,
        },
        charts: {
          decisionBreakdown,
          toolUsage: buildToolDistribution(events),
          securityTrends: buildTrendBuckets(events),
          approvalActivity,
        },
        feeds: {
          pendingApprovals: pendingApprovalsList.slice(0, 10),
          recentSecurityEvents,
          recentExecutions,
        },
        lookups: {
          agentsById: agentMap,
          toolsByName: toolMap,
        },
      };
    },
  });
}
