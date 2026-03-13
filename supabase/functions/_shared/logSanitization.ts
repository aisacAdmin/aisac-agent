/**
 * Log Sanitization Utility
 *
 * Sanitizes sensitive data before logging to prevent credential leakage.
 *
 * @module logSanitization
 */

const SENSITIVE_PATTERNS = [
  'password', 'passwd', 'pwd', 'api_key', 'apikey', 'api-key',
  'secret', 'token', 'auth', 'credential', 'private', 'key',
  'session', 'cookie', 'authorization', 'bearer', 'signature',
  'hash', 'salt',
];

function isSensitiveField(fieldName: string): boolean {
  const lowerField = fieldName.toLowerCase();
  return SENSITIVE_PATTERNS.some(pattern => lowerField.includes(pattern));
}

export function sanitizeForLogging(obj: unknown, maxDepth: number = 5): unknown {
  if (obj === null || obj === undefined) return obj;
  if (maxDepth === 0) return '[Max Depth Reached]';
  if (typeof obj !== 'object') return obj;

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeForLogging(item, maxDepth - 1));
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    if (isSensitiveField(key)) {
      if (typeof value === 'string' && value.length > 0) {
        sanitized[key] = '[REDACTED]';
      } else if (value) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = value;
      }
    } else {
      sanitized[key] = sanitizeForLogging(value, maxDepth - 1);
    }
  }
  return sanitized;
}

export function sanitizeString(str: string): string {
  let sanitized = str;
  const patterns = [
    { regex: /([?&]api[_-]?key=)[^&\s]+/gi, replacement: '$1[REDACTED]' },
    { regex: /([?&]token=)[^&\s]+/gi, replacement: '$1[REDACTED]' },
    { regex: /(Bearer|Basic)\s+[^\s]+/gi, replacement: '$1 [REDACTED]' },
    { regex: /([?&]password=)[^&\s]+/gi, replacement: '$1[REDACTED]' },
  ];
  for (const { regex, replacement } of patterns) {
    sanitized = sanitized.replace(regex, replacement);
  }
  return sanitized;
}

export function safeLog(message: string, data?: unknown): void {
  if (data === undefined) { console.log(message); return; }
  const sanitized = sanitizeForLogging(data);
  console.log(message, sanitized);
}

export function safeError(message: string, error?: unknown): void {
  if (error === undefined) { console.error(message); return; }
  if (error instanceof Error) {
    console.error(message, {
      name: error.name,
      message: sanitizeString(error.message),
      stack: error.stack ? sanitizeString(error.stack) : undefined,
    });
    return;
  }
  const sanitized = sanitizeForLogging(error);
  console.error(message, sanitized);
}
