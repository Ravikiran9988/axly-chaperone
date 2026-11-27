import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { ShieldCheck } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/Card';
import { EmptyState } from '../ui/EmptyState';
import { Skeleton } from '../ui/Skeleton';

const DECISION_COLORS = {
  allow: '#10b981',
  deny: '#f43f5e',
  require_approval: '#f59e0b',
};

export function DecisionBreakdownChart({ data = [], isLoading = false }) {
  const total = data.reduce((acc, d) => acc + (d.count || 0), 0);

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Allow vs Deny Decisions</CardTitle>
          <CardDescription>Total recorded audit decisions across all policies</CardDescription>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-56 w-full" />
        ) : total === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title="No policy decisions recorded yet"
            description="Policy evaluation and execution decisions from the gateway will appear here."
            className="py-10"
          />
        ) : (
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} margin={{ top: 10, right: 16, left: -12, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.25} />
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                <Tooltip
                  cursor={{ fill: 'rgba(148, 163, 184, 0.08)' }}
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '6px',
                    fontSize: '12px',
                    color: '#f8fafc',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={56}>
                  {data.map((entry) => (
                    <Cell key={entry.key} fill={DECISION_COLORS[entry.key] || '#38bdf8'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
