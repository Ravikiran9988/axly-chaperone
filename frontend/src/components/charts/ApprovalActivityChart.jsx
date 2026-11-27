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
import { CheckSquare } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/Card';
import { EmptyState } from '../ui/EmptyState';
import { Skeleton } from '../ui/Skeleton';

const APPROVAL_COLORS = {
  PENDING: '#f59e0b',
  EXECUTED: '#10b981',
  APPROVED: '#38bdf8',
  REJECTED: '#f43f5e',
  EXPIRED: '#64748b',
  FAILED: '#e11d48',
};

export function ApprovalActivityChart({ data = [], isLoading = false }) {
  const total = data.reduce((acc, item) => acc + (item.count || 0), 0);

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Approval Activity</CardTitle>
          <CardDescription>Human-in-the-loop approval lifecycle breakdown</CardDescription>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-56 w-full" />
        ) : total === 0 ? (
          <EmptyState
            icon={CheckSquare}
            title="No approval requests yet"
            description="Sensitive actions gated by REQUIRE_APPROVAL policies will populate this chart."
            className="py-10"
          />
        ) : (
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} margin={{ top: 10, right: 16, left: -12, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.25} />
                <XAxis dataKey="status" tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
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
                <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={44}>
                  {data.map((entry) => (
                    <Cell key={entry.status} fill={APPROVAL_COLORS[entry.status] || '#64748b'} />
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
