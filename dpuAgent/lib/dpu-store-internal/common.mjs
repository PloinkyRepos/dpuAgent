export function nowIso() {
  return new Date().toISOString();
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

export function normalizeName(value, fieldName) {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`${fieldName} is required.`);
  }
  if (normalized.includes('\0')) {
    throw new Error(`${fieldName} contains an invalid null byte.`);
  }
  return normalized;
}

export function normalizeSecretKey(value) {
  const normalized = normalizeName(value, 'key');
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(normalized)) {
    throw new Error('Secret key must be a valid environment variable name.');
  }
  return normalized;
}

export function normalizePathSegment(value, fieldName = 'name') {
  const normalized = normalizeName(value, fieldName);
  if (normalized === '.' || normalized === '..') {
    throw new Error(`${fieldName} cannot be "." or "..".`);
  }
  if (/[\\/]/.test(normalized)) {
    throw new Error(`${fieldName} cannot contain path separators.`);
  }
  return normalized;
}

export function canonicalizePrincipal(value) {
  const normalized = String(value || '').trim();
  if (!normalized) {
    return '';
  }
  if (normalized.includes('@')) {
    return normalized.toLowerCase();
  }
  const userMatch = normalized.match(/^user:(.+)$/i);
  if (userMatch) {
    const userValue = userMatch[1].trim();
    if (!userValue) {
      throw new Error('principal is invalid.');
    }
    return `user:${userValue}`;
  }
  return normalized;
}

export function normalizePrincipal(value, fieldName = 'principal') {
  const normalized = normalizeName(value, fieldName);
  return canonicalizePrincipal(normalized);
}
