import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { createPolicy, getPolicy, listPolicies, updatePolicy } from '../services/policies';

export function usePoliciesQuery(params = {}, options = {}) {
  return useQuery({
    queryKey: ['policies', params],
    queryFn: () => listPolicies(params),
    ...options,
  });
}

export function usePolicyQuery(policyId, options = {}) {
  return useQuery({
    queryKey: ['policy', policyId],
    queryFn: () => getPolicy(policyId),
    enabled: Boolean(policyId),
    ...options,
  });
}

export function useCreatePolicyMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: createPolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });
}

export function useUpdatePolicyMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ policyId, payload }) => updatePolicy(policyId, payload),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
      queryClient.invalidateQueries({ queryKey: ['policy', variables.policyId] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });
}
