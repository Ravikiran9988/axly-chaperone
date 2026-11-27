import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getTool, listTools, registerTool, updateTool } from '../services/tools';

export function useToolsQuery(params = {}, options = {}) {
  return useQuery({
    queryKey: ['tools', params],
    queryFn: () => listTools(params),
    ...options,
  });
}

export function useToolQuery(toolName, options = {}) {
  return useQuery({
    queryKey: ['tool', toolName],
    queryFn: () => getTool(toolName),
    enabled: Boolean(toolName),
    ...options,
  });
}

export function useRegisterToolMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: registerTool,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tools'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });
}

export function useUpdateToolMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ toolName, payload }) => updateTool(toolName, payload),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['tools'] });
      queryClient.invalidateQueries({ queryKey: ['tool', variables.toolName] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });
}
