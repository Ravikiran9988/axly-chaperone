import { useQuery } from '@tanstack/react-query';
import { getHealthStatus, getReadinessStatus } from '../services/health';

export function useHealthQuery(options = {}) {
  return useQuery({
    queryKey: ['system-health'],
    queryFn: getHealthStatus,
    refetchInterval: 30000,
    retry: 1,
    staleTime: 10000,
    ...options,
  });
}

export function useReadinessQuery(options = {}) {
  return useQuery({
    queryKey: ['system-readiness'],
    queryFn: getReadinessStatus,
    refetchInterval: 30000,
    retry: 1,
    staleTime: 10000,
    ...options,
  });
}
