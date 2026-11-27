import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from '../components/layout/AppShell';
import { ProtectedRoute } from '../components/layout/ProtectedRoute';
import { Login } from '../pages/Login';
import { Overview } from '../pages/Overview';
import { Agents } from '../pages/Agents';
import { AgentDetails } from '../pages/AgentDetails';
import { Tools } from '../pages/Tools';
import { Policies } from '../pages/Policies';
import { Approvals } from '../pages/Approvals';
import { SecurityEvents } from '../pages/SecurityEvents';
import { AuditLogs } from '../pages/AuditLogs';
import { Settings } from '../pages/Settings';

function ProtectedPage({ title, breadcrumbs, children }) {
  return (
    <ProtectedRoute>
      <AppShell title={title} breadcrumbs={breadcrumbs}>
        {children}
      </AppShell>
    </ProtectedRoute>
  );
}

export function AppRouter() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <ProtectedPage title="Overview" breadcrumbs={[{ label: 'Overview' }]}>
            <Overview />
          </ProtectedPage>
        }
      />
      <Route
        path="/agents"
        element={
          <ProtectedPage title="Agents" breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Agents' }]}>
            <Agents />
          </ProtectedPage>
        }
      />
      <Route
        path="/agents/:agentId"
        element={
          <ProtectedPage
            title="Agent Details"
            breadcrumbs={[
              { label: 'Overview', to: '/' },
              { label: 'Agents', to: '/agents' },
              { label: 'Details' },
            ]}
          >
            <AgentDetails />
          </ProtectedPage>
        }
      />
      <Route
        path="/tools"
        element={
          <ProtectedPage title="Tools" breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Tools' }]}>
            <Tools />
          </ProtectedPage>
        }
      />
      <Route
        path="/policies"
        element={
          <ProtectedPage title="Policies" breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Policies' }]}>
            <Policies />
          </ProtectedPage>
        }
      />
      <Route
        path="/approvals"
        element={
          <ProtectedPage title="Approval Center" breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Approvals' }]}>
            <Approvals />
          </ProtectedPage>
        }
      />
      <Route
        path="/security-events"
        element={
          <ProtectedPage
            title="Security Events"
            breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Security Events' }]}
          >
            <SecurityEvents />
          </ProtectedPage>
        }
      />
      <Route
        path="/audit-logs"
        element={
          <ProtectedPage title="Audit Logs" breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Audit Logs' }]}>
            <AuditLogs />
          </ProtectedPage>
        }
      />
      <Route
        path="/settings"
        element={
          <ProtectedPage title="Settings & Health" breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Settings' }]}>
            <Settings />
          </ProtectedPage>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
