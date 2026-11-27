/**
 * Backend Phase 2 Adapter Registry Specification
 * Matches backend/app/execution/registry.py and backend/app/adapters/*.py.
 * Note: The backend does not expose a dynamic runtime capabilities endpoint;
 * non-built-in registered tools are accurately labeled as Policy Evaluation Only.
 */
export const CONTROLLED_ADAPTER_SPECS = {
  file_tool: {
    toolName: 'file_tool',
    adapterClass: 'FileToolAdapter',
    category: 'filesystem',
    supportedActions: ['read', 'write', 'list'],
    runtimeBoundary: 'Sandboxed to CHAPERONE_SANDBOX_DIR with symlink and traversal blocking.',
    verificationMethod: 'Independently checks disk existence, byte size, and SHA-256 hash.',
    exampleResources: ['documents/invoice.txt', 'documents/*', 'private/*'],
  },
  email_tool: {
    toolName: 'email_tool',
    adapterClass: 'EmailToolAdapter',
    category: 'communication',
    supportedActions: ['create_draft', 'send', 'read'],
    runtimeBoundary: 'Local mock_emails database table only; never opens external SMTP.',
    verificationMethod: 'Queries mock_emails to confirm recipient, subject, and delivery status.',
    exampleResources: ['finance@company.com', '*@company.com', 'sent', 'drafts'],
  },
  database_tool: {
    toolName: 'database_tool',
    adapterClass: 'DatabaseToolAdapter',
    category: 'database',
    supportedActions: ['read', 'create', 'update'],
    runtimeBoundary:
      'Parameterized ORM queries restricted to demo_invoices and demo_tasks; raw SQL rejected.',
    verificationMethod: 'Queries target demo table row by ID to verify persisted fields.',
    exampleResources: ['demo_invoices', 'demo_tasks'],
  },
};

export function getToolExecutionCapabilities(tool) {
  if (!tool) {
    return {
      hasAdapter: false,
      executionState: 'unknown',
      executionLabel: 'Unknown',
      supportedActions: [],
      spec: null,
    };
  }

  const normalizedName = String(tool.name || '').toLowerCase();
  const spec = CONTROLLED_ADAPTER_SPECS[normalizedName] || null;

  if (!spec) {
    return {
      hasAdapter: false,
      executionState: 'evaluation_only',
      executionLabel: 'Evaluation Only (No Adapter)',
      supportedActions: [],
      spec: null,
    };
  }

  if (!tool.enabled) {
    return {
      hasAdapter: true,
      executionState: 'adapter_disabled',
      executionLabel: 'Executable Adapter (Disabled)',
      supportedActions: spec.supportedActions,
      spec,
    };
  }

  return {
    hasAdapter: true,
    executionState: 'executable',
    executionLabel: 'Executable Adapter Ready',
    supportedActions: spec.supportedActions,
    spec,
  };
}
