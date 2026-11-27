import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Activity } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/Card';
import { EmptyState } from '../ui/EmptyState';
import { Skeleton } from '../ui/Skeleton';

export function SecurityTrendsChart({ data = [], isLoading = false, scopeLabel }) {
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Security Event Trends</CardTitle>
          <CardDescription>
            {scopeLabel || 'Chronological decision activity derived from audit trail timestamps'}
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-56 w-full" />
        ) : data.length === 0 ? (
          <EmptyState
            icon={Activity}
            title="Insufficient historical trend data"
            description="Chronological event trends will render once gateway audit activity is recorded."
            className="py-10"
          />
        ) : (
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data} margin={{ top: 10, right: 16, left: -12, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.25} />
                <XAxis dataKey="bucket" tick={{ fontSize: 11, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '6px',
                    fontSize: '12px',
                    color: '#f8fafc',
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
                <Area
                  type="monotone"
                  dataKey="allow"
                  name="Allow"
                  stroke="#10b981"
                  fill="#10b981"
                  fillOpacity={0.16}
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="require_approval"
                  name="Approval"
                  stroke="#f59e0b"
                  fill="#f59e0b"
                  fillOpacity={0.16}
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="deny"
                  name="Deny"
                  stroke="#f43f5e"
                  fill="#f43f5e"
                  fillOpacity={0.18}
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
