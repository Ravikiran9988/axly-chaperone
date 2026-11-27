import { useQuery } from '@tanstack/react-query';
import { getAuditEvent, listAuditEvents } from '../services/audit';

export function useAuditEventsQuery(params = {}, options = {}) {
  return useQuery({
    queryKey: ['audit-events', params],
    queryFn: () => listAuditEvents(params),
    ...options,
  });
}

export function useAuditEventQuery(eventId, options = {}) {
  return useQuery({
    queryKey: ['audit-event', eventId],
    queryFn: () => getAuditEvent(eventId),
    enabled: Boolean(eventId),
    ...options,
  });
}

export function useCorrelationTimelineQuery(correlationId, options = {}) {
  return useQuery({
    queryKey: ['audit-events', 'correlation', correlationId],
    queryFn: () =>
      listAuditEvents({
        correlation_id: correlationId,
        order: 'asc',
        page: 1,
        page_size: 100,
      }),
    enabled: Boolean(correlationId),
    ...options,
  });
}
