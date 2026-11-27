import { z } from 'zod';

// Matches backend/app/schemas/auth.py
const ADMIN_USERNAME_RE = /^[A-Za-z0-9._-]{2,64}$/;

// Matches backend/app/schemas/agent.py
const AGENT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 _.-]{1,126}[A-Za-z0-9]$/;

// Matches backend/app/schemas/tool.py
const TOOL_NAME_RE = /^[a-z][a-z0-9_.-]{1,126}$/;
const TOOL_CATEGORY_RE = /^[a-z][a-z0-9_-]{1,63}$/;

// Matches backend/app/schemas/policy.py
const POLICY_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 _.:-]{1,126}[A-Za-z0-9]$/;
const POLICY_ACTION_RE = /^(?:\*|[a-z][a-z0-9_:-]{0,62})$/;

// Matches backend/app/security/resource_validator.py
const CONTROL_CHAR_RE = /[\x00-\x1f\x7f]/;
const ENCODED_TRAVERSAL_RE = /%(?:2e|2f|5c|00|25)/i;
const WINDOWS_DRIVE_RE = /^[A-Za-z]:/;
const DOMAIN_RE = /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;

export function validateResourceScopeClient(scope) {
  if (typeof scope !== 'string') return 'Resource scope is required.';
  if (scope !== scope.trim() || !scope.trim()) {
    return 'Empty or leading/trailing whitespace is not permitted.';
  }
  if (scope.length > 512) return 'Resource scope cannot exceed 512 characters.';
  if (CONTROL_CHAR_RE.test(scope)) return 'Control characters are prohibited.';
  if (ENCODED_TRAVERSAL_RE.test(scope)) {
    return 'Percent-encoded path or null sequences are prohibited.';
  }
  if (scope.includes('?')) return 'Question-mark wildcards are not permitted.';
  if (scope.includes('\\')) return 'Backslashes are prohibited in resource scopes.';
  if (scope === '*') return null;

  if (scope.startsWith('*@')) {
    const domain = scope.slice(2).toLowerCase();
    if (domain.includes('*') || !DOMAIN_RE.test(domain)) {
      return "Invalid domain wildcard scope; expected '*@domain.tld'.";
    }
    return null;
  }

  if (scope.endsWith('/*')) {
    const prefix = scope.slice(0, -2);
    if (!prefix || prefix.includes('*')) {
      return "Wildcards are only allowed as '*' or a single trailing '/*'.";
    }
    if (!prefix.includes('://')) {
      if (prefix.startsWith('/') || WINDOWS_DRIVE_RE.test(prefix)) {
        return 'Absolute or drive-prefixed paths are prohibited.';
      }
      const segments = prefix.split('/');
      if (segments.some((seg) => seg === '' || seg === '.' || seg === '..')) {
        return 'Path traversal or empty/dot segments are prohibited.';
      }
    }
    return null;
  }

  if (scope.includes('*')) {
    return "Supported wildcards: '*', '<prefix>/*', '*@<domain>', or exact match.";
  }

  if (!scope.includes('://') && (scope.startsWith('/') || WINDOWS_DRIVE_RE.test(scope))) {
    return 'Absolute paths or drive prefixes are prohibited.';
  }
  if (!scope.includes('://')) {
    const segments = scope.split('/');
    if (segments.some((seg) => seg === '' || seg === '.' || seg === '..')) {
      return 'Empty or dot traversal segments are prohibited.';
    }
  }
  return null;
}

export const loginCredentialsSchema = z.object({
  username: z
    .string()
    .trim()
    .min(2, 'Username must be at least 2 characters.')
    .max(64, 'Username is too long.')
    .refine(
      (val) => ADMIN_USERNAME_RE.test(val),
      'Username may contain letters, digits, or . _ -'
    ),
  password: z.string().min(1, 'Password is required.').max(256, 'Password is too long.'),
});

export const loginBootstrapSchema = z.object({
  adminKey: z
    .string()
    .trim()
    .min(1, 'Bootstrap administrator key is required.')
    .max(512, 'Bootstrap administrator key is too long.'),
});

export const agentCreateSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, 'Agent name must be at least 2 characters.')
    .max(128, 'Agent name must be at most 128 characters.')
    .regex(
      AGENT_NAME_RE,
      "Must start/end with alphanumeric characters and use only letters, digits, spaces, '.', '_', or '-'."
    ),
  description: z
    .string()
    .trim()
    .max(1000, 'Description cannot exceed 1000 characters.')
    .optional()
    .default(''),
});

export const toolCreateSchema = z.object({
  name: z
    .string()
    .trim()
    .toLowerCase()
    .min(2, 'Tool name must be at least 2 characters.')
    .max(128, 'Tool name must be at most 128 characters.')
    .regex(
      TOOL_NAME_RE,
      "Must start with a lowercase letter and contain only lowercase letters, digits, '.', '_', or '-'."
    ),
  description: z
    .string()
    .trim()
    .min(1, 'Description is required.')
    .max(1000, 'Description cannot exceed 1000 characters.'),
  category: z
    .string()
    .trim()
    .toLowerCase()
    .min(2, 'Category must be at least 2 characters.')
    .max(64, 'Category must be at most 64 characters.')
    .regex(
      TOOL_CATEGORY_RE,
      "Must start with a lowercase letter and contain only lowercase letters, digits, '_', or '-'."
    ),
  risk_level: z.enum(['low', 'medium', 'high', 'critical']),
  enabled: z.boolean().default(true),
});

export const toolUpdateSchema = z.object({
  description: z
    .string()
    .trim()
    .min(1, 'Description cannot be empty.')
    .max(1000, 'Description cannot exceed 1000 characters.'),
  category: z
    .string()
    .trim()
    .toLowerCase()
    .min(2, 'Category must be at least 2 characters.')
    .max(64, 'Category must be at most 64 characters.')
    .regex(
      TOOL_CATEGORY_RE,
      "Must start with a lowercase letter and contain only lowercase letters, digits, '_', or '-'."
    ),
  risk_level: z.enum(['low', 'medium', 'high', 'critical']),
  enabled: z.boolean(),
});

export const policyCreateSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, 'Policy name must be at least 2 characters.')
    .max(128, 'Policy name must be at most 128 characters.')
    .regex(POLICY_NAME_RE, 'Policy name contains unsupported leading/trailing or special characters.'),
  description: z
    .string()
    .trim()
    .max(1000, 'Description cannot exceed 1000 characters.')
    .optional()
    .default(''),
  agent_id: z.string().optional().default(''),
  tool_name: z
    .string()
    .trim()
    .toLowerCase()
    .min(2, 'Select a registered tool.')
    .regex(TOOL_NAME_RE, 'Invalid tool name format.'),
  action: z
    .string()
    .trim()
    .toLowerCase()
    .min(1, 'Action is required.')
    .max(64, 'Action cannot exceed 64 characters.')
    .regex(POLICY_ACTION_RE, "Action must be '*' or a lowercase identifier (e.g. read, send)."),
  resource_scope: z
    .string()
    .min(1, 'Resource scope is required.')
    .max(512, 'Resource scope cannot exceed 512 characters.')
    .superRefine((val, ctx) => {
      const err = validateResourceScopeClient(val);
      if (err) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: err });
      }
    }),
  decision: z.enum(['allow', 'deny', 'require_approval']),
  priority: z.coerce
    .number()
    .int('Priority must be a whole integer.')
    .min(0, 'Priority must be between 0 and 10000.')
    .max(10000, 'Priority must be between 0 and 10000.'),
  enabled: z.boolean().default(true),
});

export const policyUpdateSchema = z.object({
  description: z
    .string()
    .trim()
    .max(1000, 'Description cannot exceed 1000 characters.')
    .optional()
    .default(''),
  action: z
    .string()
    .trim()
    .toLowerCase()
    .min(1, 'Action is required.')
    .max(64, 'Action cannot exceed 64 characters.')
    .regex(POLICY_ACTION_RE, "Action must be '*' or a lowercase identifier."),
  resource_scope: z
    .string()
    .min(1, 'Resource scope is required.')
    .max(512, 'Resource scope cannot exceed 512 characters.')
    .superRefine((val, ctx) => {
      const err = validateResourceScopeClient(val);
      if (err) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: err });
      }
    }),
  decision: z.enum(['allow', 'deny', 'require_approval']),
  priority: z.coerce
    .number()
    .int('Priority must be a whole integer.')
    .min(0, 'Priority must be between 0 and 10000.')
    .max(10000, 'Priority must be between 0 and 10000.'),
  enabled: z.boolean(),
});

export const approvalCommentSchema = z.object({
  comment: z
    .string()
    .trim()
    .max(1000, 'Comment cannot exceed 1000 characters.')
    .optional()
    .default(''),
});

export function detectBroadPolicyRisks({ agent_id, action, resource_scope, decision }) {
  const warnings = [];
  if (decision !== 'allow') return warnings;

  if (!agent_id) {
    warnings.push('Global scope: applies to EVERY active agent in the gateway.');
  }
  if (action === '*') {
    warnings.push('Wildcard action (*): permits ALL actions supported by this tool.');
  }
  if (resource_scope === '*') {
    warnings.push('Unrestricted resource scope (*): permits access to ANY target resource.');
  } else if (resource_scope.endsWith('/*')) {
    warnings.push(`Broad prefix scope (${resource_scope}): grants access to all resources under this prefix.`);
  }
  return warnings;
}
