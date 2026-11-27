import { Activity, Database, Info, Moon, RefreshCw, Shield, Sun, Terminal } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { useHealthQuery, useReadinessQuery } from '../hooks/useHealth';
import { API_BASE_URL, API_TIMEOUT_MS, AUTH_MODE } from '../services/api';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { Skeleton } from '../components/ui/Skeleton';

export function Settings() {
  const { user } = useAuth();
  const { theme, setTheme } = useTheme();
  const healthQuery = useHealthQuery();
  const readinessQuery = useReadinessQuery();

  const apiUp = healthQuery.isSuccess && healthQuery.data?.status === 'ok';
  const dbReady = readinessQuery.isSuccess && readinessQuery.data?.database === 'connected';

  return (
    <div className="space-y-6">
      <p className="text-xs text-slate-500 dark:text-slate-400">
        Operational diagnostics and client console configuration. Environment secrets and credentials are never exposed.
      </p>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* System Health */}
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Backend Health & Readiness</CardTitle>
              <CardDescription>Live telemetry from /health and /ready endpoints</CardDescription>
            </div>
            <Button
              variant="outline"
              size="xs"
              onClick={() => {
                healthQuery.refetch();
                readinessQuery.refetch();
              }}
              isLoading={healthQuery.isFetching || readinessQuery.isFetching}
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Probe
            </Button>
          </CardHeader>
          <CardContent className="space-y-4 text-xs">
            {healthQuery.isLoading ? (
              <Skeleton className="h-28 w-full" />
            ) : (
              <div className="divide-y divide-slate-200 dark:divide-slate-800/80">
                <div className="flex items-center justify-between py-2.5">
                  <span className="flex items-center gap-2 text-slate-600 dark:text-slate-400">
                    <Activity className="h-4 w-4" />
                    API Connection (/health)
                  </span>
                  <StatusBadge
                    value={apiUp ? 'active' : 'failed'}
                    labelOverride={apiUp ? `CONNECTED (${healthQuery.data.latencyMs}ms)` : 'UNREACHABLE'}
                  />
                </div>
                <div className="flex items-center justify-between py-2.5">
                  <span className="flex items-center gap-2 text-slate-600 dark:text-slate-400">
                    <Database className="h-4 w-4" />
                    Database Readiness (/ready)
                  </span>
                  <StatusBadge
                    value={dbReady ? 'verified' : 'failed'}
                    labelOverride={
                      readinessQuery.data?.database
                        ? readinessQuery.data.database.toUpperCase()
                        : 'UNAVAILABLE'
                    }
                  />
                </div>
                <div className="flex items-center justify-between py-2.5">
                  <span className="text-slate-600 dark:text-slate-400">Service Name</span>
                  <span className="font-medium text-slate-900 dark:text-slate-100">
                    {healthQuery.data?.service || 'AXLY Chaperone'}
                  </span>
                </div>
                <div className="flex items-center justify-between py-2.5">
                  <span className="text-slate-600 dark:text-slate-400">Application Version</span>
                  <span className="font-mono text-slate-900 dark:text-slate-100">
                    {healthQuery.data?.version ? `v${healthQuery.data.version}` : 'Unavailable'}
                  </span>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* MCP & Connection Info */}
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Gateway & MCP Runtime Contract</CardTitle>
              <CardDescription>Client connection settings and exposed subsystems</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="space-y-4 text-xs">
            <div className="divide-y divide-slate-200 dark:divide-slate-800/80">
              <div className="flex items-center justify-between py-2.5">
                <span className="text-slate-600 dark:text-slate-400">Backend Target Base URL</span>
                <code className="font-mono text-slate-900 dark:text-slate-100">
                  {API_BASE_URL || 'Same-Origin Dev Proxy (/api)'}
                </code>
              </div>
              <div className="flex items-center justify-between py-2.5">
                <span className="text-slate-600 dark:text-slate-400">HTTP Request Timeout</span>
                <span className="font-mono tabular-nums">{API_TIMEOUT_MS} ms</span>
              </div>
              <div className="flex items-center justify-between py-2.5">
                <span className="flex items-center gap-2 text-slate-600 dark:text-slate-400">
                  <Shield className="h-4 w-4" />
                  Admin Session Mode
                </span>
                <span className="font-mono text-slate-900 dark:text-slate-100">
                  {AUTH_MODE} ({user?.actor || 'admin'})
                </span>
              </div>
              <div className="flex items-center justify-between py-2.5">
                <span className="flex items-center gap-2 text-slate-600 dark:text-slate-400">
                  <Terminal className="h-4 w-4" />
                  MCP Server Status
                </span>
                <StatusBadge value="not_applicable" labelOverride="STDIO / NOT EXPOSED OVER HTTP" />
              </div>
            </div>

            <div className="flex items-start gap-2 rounded-md border border-slate-200 bg-slate-50 p-3 text-[11px] text-slate-600 dark:border-slate-800 dark:bg-obsidian-950 dark:text-slate-400">
              <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sky-500" />
              <span>
                The Chaperone MCP server runs over <code>stdio</code> transport (
                <code>python -m app.adapters.mcp.server</code>) and is not exposed as an HTTP health
                endpoint in Phase 1/2. All MCP calls route through <code>GatewayService</code> and
                appear in Audit Logs.
              </span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Console Theme Preference */}
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Interface Appearance</CardTitle>
            <CardDescription>Dark-first security interface with optional light theme</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-3">
          <Button
            variant={theme === 'dark' ? 'primary' : 'outline'}
            size="sm"
            onClick={() => setTheme('dark')}
          >
            <Moon className="h-3.5 w-3.5" />
            Dark Mode (Default)
          </Button>
          <Button
            variant={theme === 'light' ? 'primary' : 'outline'}
            size="sm"
            onClick={() => setTheme('light')}
          >
            <Sun className="h-3.5 w-3.5" />
            Light Mode
          </Button>
        </CardContent>
      </Card>

      {/* Documented Backend Gaps */}
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Backend API Coverage & Phase 4 Notes</CardTitle>
            <CardDescription>
              Features intentionally deferred until backend endpoints are added
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="space-y-2 text-xs text-slate-600 dark:text-slate-300">
          <ul className="list-disc space-y-1.5 pl-5">
            <li>
              <strong>Admin Login / HTTP-only Cookie Sessions:</strong> Backend currently uses single-key{' '}
              <code>X-Admin-Key</code> validation; frontend holds this credential strictly in memory and
              exposes a Phase 4 <code>VITE_AUTH_MODE=session_cookie</code> contract.
            </li>
            <li>
              <strong>Aggregated Metrics Endpoint:</strong> Overview KPIs and charts compute directly from
              real <code>PaginatedResponse.total</code> counts and the fetched audit/approval windows.
            </li>
            <li>
              <strong>Policy & Agent Deletion / Key Rotation:</strong> Not implemented in Phase 1/2 backend;
              disable toggles are provided instead to preserve append-only audit integrity.
            </li>
            <li>
              <strong>Dynamic Tool Capabilities Endpoint:</strong> Execution readiness distinguishes known
              Phase 2 adapters (<code>file_tool</code>, <code>email_tool</code>,{' '}
              <code>database_tool</code>) from metadata-only tools.
            </li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
