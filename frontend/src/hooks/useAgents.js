import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getAgent, listAgents, registerAgent, updateAgentStatus } from '../services/agents';

export function useAgentsQuery(params = {}, options = {}) {
  return useQuery({
    queryKey: ['agents', params],
    queryFn: () => listAgents(params),
    ...options,
  });
}

export function useAgentQuery(agentId, options = {}) {
  return useQuery({
    queryKey: ['agent', agentId],
    queryFn: () => getAgent(agentId),
    enabled: Boolean(agentId),
    ...options,
  });
}

export function useRegisterAgentMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: registerAgent,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agents'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });
}

export function useUpdateAgentStatusMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ agentId, status }) => updateAgentStatus(agentId, status),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['agents'] });
      queryClient.invalidateQueries({ queryKey: ['agent', variables.agentId] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });
}
