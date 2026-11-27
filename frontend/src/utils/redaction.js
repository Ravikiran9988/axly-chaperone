const SECRET_VALUE_PATTERNS = [
  /axly_(?:ag|adm)_[A-Za-z0-9_-]+/g,
  /pbkdf2_sha256\$\d+\$[A-Za-z0-9_=-]+\$[A-Za-z0-9_=-]+/g,
  /(x-agent-key|x-admin-key|authorization|api_key|password)\s*[:=]\s*[^\s,;"']+/gi,
  /Bearer\s+[A-Za-z0-9._~+/=-]+/gi,
];

const SENSITIVE_KEY_RE =
  /(^|_|-)(password|passwd|secret|token|api_?key|private_?key|access_?key|auth|authorization|cookie|credential|session_?id|x-admin-key|x-agent-key)($|_|-)/i;

export function redactSecretString(value) {
  if (typeof value !== 'string') return value;
  let result = value;
  for (const pattern of SECRET_VALUE_PATTERNS) {
    result = result.replace(pattern, '[REDACTED]');
  }
  return result;
}

export function redactSensitivePayload(input, depth = 0) {
  if (depth > 12) return '[TRUNCATED]';
  if (input === null || input === undefined) return input;
  if (typeof input === 'string') return redactSecretString(input);
  if (typeof input !== 'object') return input;

  if (Array.isArray(input)) {
    return input.map((item) => redactSensitivePayload(item, depth + 1));
  }

  const sanitized = {};
  for (const [key, val] of Object.entries(input)) {
    if (SENSITIVE_KEY_RE.test(key)) {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = redactSensitivePayload(val, depth + 1);
    }
  }
  return sanitized;
}
