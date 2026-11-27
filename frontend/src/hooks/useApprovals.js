import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { approveRequest, getApproval, listApprovals, rejectRequest } from '../services/approvals';

export function useApprovalsQuery(params = {}, options = {}) {
  return useQuery({
    queryKey: ['approvals', params],
    queryFn: () => listApprovals(params),
    ...options,
  });
}

export function usePendingApprovalsCount(enabled = true) {
  return useQuery({
    queryKey: ['approvals', 'pending-summary'],
    queryFn: () => listApprovals({ status: 'pending', page: 1, page_size: 5 }),
    enabled,
    refetchInterval: 30000,
    staleTime: 10000,
  });
}

export function useApprovalQuery(approvalId, options = {}) {
  return useQuery({
    queryKey: ['approval', approvalId],
    queryFn: () => getApproval(approvalId),
    enabled: Boolean(approvalId),
    ...options,
  });
}

export function useApproveMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ approvalId, comment, executeNow }) =>
      approveRequest(approvalId, { comment, executeNow }),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['approvals'] });
      queryClient.invalidateQueries({ queryKey: ['approval', variables.approvalId] });
      queryClient.invalidateQueries({ queryKey: ['audit-events'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });
}

export function useRejectMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ approvalId, comment }) => rejectRequest(approvalId, { comment }),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['approvals'] });
      queryClient.invalidateQueries({ queryKey: ['approval', variables.approvalId] });
      queryClient.invalidateQueries({ queryKey: ['audit-events'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });
}
