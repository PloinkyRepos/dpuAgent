import {
  canonicalizePrincipal,
  isNonEmptyString,
  nowIso
} from './common.mjs';

const IDENTITY_ALIAS_KEYS = ['emails', 'userIds', 'usernames', 'ssoSubjects', 'issuers'];
const RESOURCE_PERMISSION_KEYS = {
  secret: 'secrets',
  confidential: 'objects'
};

function pushUnique(list, value, normalizer = null) {
  const normalized = typeof normalizer === 'function' ? normalizer(value) : String(value || '').trim();
  if (!normalized) {
    return false;
  }
  if (!list.includes(normalized)) {
    list.push(normalized);
    return true;
  }
  return false;
}

function toStringList(input, normalizer = null) {
  const values = Array.isArray(input) ? input : [];
  const output = [];
  for (const value of values) {
    pushUnique(output, value, normalizer);
  }
  return output.sort((a, b) => String(a).localeCompare(String(b)));
}

function normalizeAliasBucket(input = {}) {
  return {
    emails: toStringList(input.emails, (value) => {
      const normalized = String(value || '').trim().toLowerCase();
      return normalized.includes('@') ? normalized : '';
    }),
    userIds: toStringList(input.userIds),
    usernames: toStringList(input.usernames),
    ssoSubjects: toStringList(input.ssoSubjects),
    issuers: toStringList(input.issuers)
  };
}

function normalizeClaimBucket(input = {}) {
  return {
    roles: toStringList(input.roles)
  };
}

function normalizePrincipalEntry(input = {}) {
  const aliases = normalizeAliasBucket(input.aliases || {});
  const claims = normalizeClaimBucket(input.claims || {});
  const createdAt = isNonEmptyString(input.createdAt) ? String(input.createdAt).trim() : '';
  const updatedAt = isNonEmptyString(input.updatedAt) ? String(input.updatedAt).trim() : '';
  return {
    aliases,
    claims,
    createdAt,
    updatedAt
  };
}

function normalizeAclRecord(input = {}) {
  const acl = {};
  const rawAcl = input.acl && typeof input.acl === 'object' ? input.acl : {};
  for (const [principal, role] of Object.entries(rawAcl)) {
    const normalizedPrincipal = canonicalizePrincipal(principal);
    const normalizedRole = String(role || '').trim().toLowerCase();
    if (normalizedPrincipal && normalizedRole) {
      acl[normalizedPrincipal] = normalizedRole;
    }
  }
  return {
    acl,
    updatedAt: isNonEmptyString(input.updatedAt) ? String(input.updatedAt).trim() : ''
  };
}

function mergeClaims(...inputs) {
  const merged = {};
  for (const input of inputs) {
    if (!input || typeof input !== 'object') {
      continue;
    }
    Object.assign(merged, input);
  }
  return merged;
}

function collectRoleValues(claims = {}, user = {}) {
  const values = [];
  const pushRoles = (input) => {
    if (Array.isArray(input)) {
      input.forEach((value) => {
        if (isNonEmptyString(value)) {
          values.push(String(value).trim());
        }
      });
      return;
    }
    if (isNonEmptyString(input)) {
      values.push(String(input).trim());
    }
  };

  pushRoles(user.roles);
  pushRoles(claims.roles);
  pushRoles(claims.groups);
  pushRoles(claims.permissions);
  pushRoles(claims.scope && typeof claims.scope === 'string' ? claims.scope.split(/\s+/) : []);
  pushRoles(claims.realm_access?.roles);

  if (claims.resource_access && typeof claims.resource_access === 'object') {
    for (const resource of Object.values(claims.resource_access)) {
      pushRoles(resource?.roles);
    }
  }

  return toStringList(values);
}

export function defaultPermissionsManifest() {
  return {
    version: 1,
    identities: {
      principals: {}
    },
    permissions: {
      secrets: {},
      objects: {}
    }
  };
}

export function normalizePermissionsManifest(input = {}) {
  const base = defaultPermissionsManifest();
  const principals = input?.identities?.principals && typeof input.identities.principals === 'object'
    ? input.identities.principals
    : {};
  const normalizedPrincipals = {};
  for (const [principalId, entry] of Object.entries(principals)) {
    const normalizedPrincipalId = canonicalizePrincipal(principalId);
    if (!normalizedPrincipalId) {
      continue;
    }
    normalizedPrincipals[normalizedPrincipalId] = normalizePrincipalEntry(entry);
  }

  const permissions = input?.permissions && typeof input.permissions === 'object'
    ? input.permissions
    : {};
  const secrets = permissions.secrets && typeof permissions.secrets === 'object'
    ? permissions.secrets
    : {};
  const objects = permissions.objects && typeof permissions.objects === 'object'
    ? permissions.objects
    : {};
  const normalizedSecrets = {};
  for (const [resourceId, entry] of Object.entries(secrets)) {
    const normalizedResourceId = String(resourceId || '').trim();
    if (!normalizedResourceId) {
      continue;
    }
    normalizedSecrets[normalizedResourceId] = normalizeAclRecord(entry);
  }
  const normalizedObjects = {};
  for (const [resourceId, entry] of Object.entries(objects)) {
    const normalizedResourceId = String(resourceId || '').trim();
    if (!normalizedResourceId) {
      continue;
    }
    normalizedObjects[normalizedResourceId] = normalizeAclRecord(entry);
  }

  return {
    version: Number.isFinite(Number(input.version)) ? Number(input.version) : base.version,
    identities: {
      principals: normalizedPrincipals
    },
    permissions: {
      secrets: normalizedSecrets,
      objects: normalizedObjects
    }
  };
}

export function extractIdentityHints(authInfo = null) {
  const user = authInfo?.user && typeof authInfo.user === 'object' ? authInfo.user : {};
  const rootClaims = authInfo?.claims && typeof authInfo.claims === 'object' ? authInfo.claims : {};
  const userClaims = user.claims && typeof user.claims === 'object' ? user.claims : {};
  const tokenClaims = authInfo?.token?.claims && typeof authInfo.token.claims === 'object' ? authInfo.token.claims : {};
  const claims = mergeClaims(rootClaims, userClaims, tokenClaims);

  const email = String(user.email || claims.email || '').trim().toLowerCase();
  const username = String(
    user.username
    || user.name
    || claims.preferred_username
    || claims.username
    || ''
  ).trim();
  const id = String(
    user.id
    || claims.user_id
    || claims.uid
    || claims.sid
    || ''
  ).trim();
  const ssoSubject = String(
    authInfo?.subject
    || user.sub
    || claims.sub
    || ''
  ).trim();
  const issuer = String(
    authInfo?.issuer
    || claims.iss
    || ''
  ).trim();

  return {
    email,
    username,
    id,
    ssoSubject,
    issuer,
    roles: collectRoleValues(claims, user),
    claims
  };
}

export function getPermissionEntry(manifest, kind, resourceId) {
  const bucketName = RESOURCE_PERMISSION_KEYS[kind];
  if (!bucketName) {
    return null;
  }
  const bucket = manifest?.permissions?.[bucketName];
  if (!bucket || typeof bucket !== 'object') {
    return null;
  }
  const normalizedResourceId = String(resourceId || '').trim();
  if (!normalizedResourceId) {
    return null;
  }
  const entry = bucket[normalizedResourceId];
  return entry && typeof entry === 'object' ? entry : null;
}

export function getPermissionAcl(manifest, kind, resourceId) {
  const entry = getPermissionEntry(manifest, kind, resourceId);
  return entry && entry.acl && typeof entry.acl === 'object'
    ? entry.acl
    : null;
}

export function ensurePermissionEntry(manifest, kind, resourceId) {
  const bucketName = RESOURCE_PERMISSION_KEYS[kind];
  if (!bucketName) {
    throw new Error(`Unsupported permission kind: ${kind}`);
  }
  const normalizedResourceId = String(resourceId || '').trim();
  if (!normalizedResourceId) {
    throw new Error('Permission resource id is required.');
  }
  if (!manifest.permissions || typeof manifest.permissions !== 'object') {
    manifest.permissions = defaultPermissionsManifest().permissions;
  }
  if (!manifest.permissions[bucketName] || typeof manifest.permissions[bucketName] !== 'object') {
    manifest.permissions[bucketName] = {};
  }
  if (!manifest.permissions[bucketName][normalizedResourceId] || typeof manifest.permissions[bucketName][normalizedResourceId] !== 'object') {
    manifest.permissions[bucketName][normalizedResourceId] = {
      acl: {},
      updatedAt: ''
    };
  }
  return manifest.permissions[bucketName][normalizedResourceId];
}

export function setPermissionRole(manifest, kind, resourceId, principalId, role) {
  const normalizedPrincipalId = canonicalizePrincipal(principalId);
  if (!normalizedPrincipalId) {
    return false;
  }
  const entry = ensurePermissionEntry(manifest, kind, resourceId);
  if (!entry.acl || typeof entry.acl !== 'object') {
    entry.acl = {};
  }
  if (entry.acl[normalizedPrincipalId] === role) {
    return false;
  }
  entry.acl[normalizedPrincipalId] = role;
  entry.updatedAt = nowIso();
  return true;
}

export function removePermissionRole(manifest, kind, resourceId, principalId) {
  const normalizedPrincipalId = canonicalizePrincipal(principalId);
  if (!normalizedPrincipalId) {
    return false;
  }
  const entry = getPermissionEntry(manifest, kind, resourceId);
  if (!entry?.acl || !Object.prototype.hasOwnProperty.call(entry.acl, normalizedPrincipalId)) {
    return false;
  }
  delete entry.acl[normalizedPrincipalId];
  entry.updatedAt = nowIso();
  return true;
}

export function deletePermissionEntry(manifest, kind, resourceId) {
  const bucketName = RESOURCE_PERMISSION_KEYS[kind];
  if (!bucketName) {
    return false;
  }
  const normalizedResourceId = String(resourceId || '').trim();
  if (!normalizedResourceId) {
    return false;
  }
  const bucket = manifest?.permissions?.[bucketName];
  if (!bucket || typeof bucket !== 'object' || !Object.prototype.hasOwnProperty.call(bucket, normalizedResourceId)) {
    return false;
  }
  delete bucket[normalizedResourceId];
  return true;
}

export function resolvePrincipalFromManifest(manifest, authInfo = null) {
  const hints = extractIdentityHints(authInfo);
  const principals = manifest?.identities?.principals;
  if (!principals || typeof principals !== 'object') {
    return '';
  }

  for (const [principalId, entry] of Object.entries(principals)) {
    const aliases = entry?.aliases || {};
    if (hints.email && Array.isArray(aliases.emails) && aliases.emails.includes(hints.email)) {
      return principalId;
    }
    if (hints.id && Array.isArray(aliases.userIds) && aliases.userIds.includes(hints.id)) {
      return principalId;
    }
    if (hints.username && Array.isArray(aliases.usernames) && aliases.usernames.includes(hints.username)) {
      return principalId;
    }
    if (hints.ssoSubject && Array.isArray(aliases.ssoSubjects) && aliases.ssoSubjects.includes(hints.ssoSubject)) {
      if (!Array.isArray(aliases.issuers) || !aliases.issuers.length || !hints.issuer || aliases.issuers.includes(hints.issuer)) {
        return principalId;
      }
    }
  }

  return '';
}

export function resolvePrincipalReference(manifest, value = '') {
  const normalizedValue = String(value || '').trim();
  if (!normalizedValue) {
    return '';
  }

  const canonicalValue = canonicalizePrincipal(normalizedValue);
  const principals = manifest?.identities?.principals;
  if (!principals || typeof principals !== 'object') {
    return canonicalValue;
  }
  if (canonicalValue && Object.prototype.hasOwnProperty.call(principals, canonicalValue)) {
    return canonicalValue;
  }

  const normalizedEmail = normalizedValue.includes('@') ? normalizedValue.toLowerCase() : '';
  for (const [principalId, entry] of Object.entries(principals)) {
    const aliases = entry?.aliases || {};
    if (normalizedEmail && Array.isArray(aliases.emails) && aliases.emails.includes(normalizedEmail)) {
      return principalId;
    }
    if (Array.isArray(aliases.userIds) && aliases.userIds.includes(normalizedValue)) {
      return principalId;
    }
    if (Array.isArray(aliases.usernames) && aliases.usernames.includes(normalizedValue)) {
      return principalId;
    }
    if (Array.isArray(aliases.ssoSubjects) && aliases.ssoSubjects.includes(normalizedValue)) {
      return principalId;
    }
  }

  return canonicalValue;
}

export function upsertPrincipalIdentity(manifest, principalId, hints = {}) {
  const normalizedPrincipalId = canonicalizePrincipal(principalId);
  if (!normalizedPrincipalId) {
    return false;
  }
  if (!manifest.identities || typeof manifest.identities !== 'object') {
    manifest.identities = defaultPermissionsManifest().identities;
  }
  if (!manifest.identities.principals || typeof manifest.identities.principals !== 'object') {
    manifest.identities.principals = {};
  }

  const existing = manifest.identities.principals[normalizedPrincipalId];
  const entry = existing
    ? normalizePrincipalEntry(existing)
    : normalizePrincipalEntry({});
  const timestamp = nowIso();
  if (!entry.createdAt) {
    entry.createdAt = timestamp;
  }

  let changed = false;
  changed = pushUnique(entry.aliases.emails, hints.email, (value) => String(value || '').trim().toLowerCase()) || changed;
  changed = pushUnique(entry.aliases.userIds, hints.id) || changed;
  changed = pushUnique(entry.aliases.usernames, hints.username) || changed;
  changed = pushUnique(entry.aliases.ssoSubjects, hints.ssoSubject) || changed;
  changed = pushUnique(entry.aliases.issuers, hints.issuer) || changed;

  const roles = Array.isArray(hints.roles) ? hints.roles : [];
  for (const role of roles) {
    changed = pushUnique(entry.claims.roles, role) || changed;
  }

  if (changed || !existing) {
    entry.updatedAt = timestamp;
    entry.aliases = normalizeAliasBucket(entry.aliases);
    entry.claims = normalizeClaimBucket(entry.claims);
    manifest.identities.principals[normalizedPrincipalId] = entry;
  }

  return changed || !existing;
}
