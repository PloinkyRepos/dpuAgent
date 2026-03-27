import { randomUUID } from 'node:crypto';

import {
  canonicalizePrincipal,
  isNonEmptyString,
  normalizeName
} from './common.mjs';
import {
  extractIdentityHints,
  resolvePrincipalFromManifest
} from './permissions-manifest.mjs';

export const SECRET_ROLE_ORDER = ['access', 'read', 'write'];
export const CONFIDENTIAL_ROLE_ORDER = ['access', 'read', 'comment', 'write'];

export function cloneAcl(input) {
  const output = {};
  if (!input || typeof input !== 'object') {
    return output;
  }
  for (const [principal, role] of Object.entries(input)) {
    const normalizedPrincipal = canonicalizePrincipal(principal);
    if (normalizedPrincipal && isNonEmptyString(role)) {
      output[normalizedPrincipal] = String(role).trim().toLowerCase();
    }
  }
  return output;
}

export function roleAllows(role, requiredRole, roleOrder) {
  const current = roleOrder.indexOf(role);
  const required = roleOrder.indexOf(requiredRole);
  if (required < 0) {
    throw new Error(`Unsupported permission: ${requiredRole}`);
  }
  return current >= required;
}

export function secretRoleAllows(role, requiredRole) {
  if (requiredRole === 'comment') {
    return false;
  }
  return roleAllows(role, requiredRole, SECRET_ROLE_ORDER);
}

export function confidentialRoleAllows(role, requiredRole) {
  return roleAllows(role, requiredRole, CONFIDENTIAL_ROLE_ORDER);
}

export function pickMaxRole(roleCandidates, roleOrder) {
  let bestRole = null;
  let bestIndex = -1;
  for (const role of roleCandidates) {
    const index = roleOrder.indexOf(role);
    if (index > bestIndex) {
      bestRole = role;
      bestIndex = index;
    }
  }
  return bestRole;
}

export function aclEntries(acl = {}) {
  return Object.entries(acl)
    .filter(([principal, role]) => isNonEmptyString(principal) && isNonEmptyString(role))
    .map(([principal, role]) => ({ principal, role }))
    .sort((a, b) => a.principal.localeCompare(b.principal));
}

export function normalizeCommentRecords(input, nowIso) {
  if (!Array.isArray(input)) {
    return [];
  }
  return input
    .filter((entry) => entry && typeof entry === 'object')
    .map((entry) => ({
      id: normalizeName(entry.id || randomUUID(), 'comment id'),
      authorPrincipal: canonicalizePrincipal(entry.authorPrincipal || ''),
      userEmail: String(entry.userEmail || '').trim().toLowerCase(),
      message: normalizeName(entry.message || '', 'comment message'),
      createdAt: isNonEmptyString(entry.createdAt) ? String(entry.createdAt).trim() : nowIso(),
      updatedAt: isNonEmptyString(entry.updatedAt) ? String(entry.updatedAt).trim() : nowIso()
    }));
}

export function serializeConfidentialComments(objectRecord, actor, canDeleteAnyComments, nowIso) {
  const comments = normalizeCommentRecords(objectRecord.comments, nowIso);
  return comments.map((entry) => ({
    id: entry.id,
    authorPrincipal: entry.authorPrincipal,
    userEmail: entry.userEmail,
    message: entry.message,
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
    canDelete: Boolean(canDeleteAnyComments || entry.authorPrincipal === actor.principalId)
  }));
}

export function resolveActor(authInfo = null, permissionsManifest = null) {
  const hints = extractIdentityHints(authInfo);
  const manifestPrincipalId = permissionsManifest
    ? resolvePrincipalFromManifest(permissionsManifest, authInfo)
    : '';
  const principalId = manifestPrincipalId
    || hints.email
    || (hints.id ? canonicalizePrincipal(`user:${hints.id}`) : '')
    || (hints.username ? canonicalizePrincipal(`user:${hints.username}`) : '')
    || (hints.ssoSubject ? canonicalizePrincipal(`sso:${hints.ssoSubject}`) : '');
  return {
    principalId,
    email: hints.email,
    username: hints.username,
    id: hints.id,
    ssoSubject: hints.ssoSubject,
    issuer: hints.issuer,
    roles: Array.isArray(hints.roles) ? [...hints.roles] : [],
    claims: hints.claims && typeof hints.claims === 'object' ? { ...hints.claims } : {},
    sessionId: String(authInfo?.sessionId || '').trim(),
    authenticated: Boolean(principalId)
  };
}

export function requireAuthenticatedActor(authInfo = null, permissionsManifest = null) {
  const actor = resolveActor(authInfo, permissionsManifest);
  if (!actor.authenticated) {
    throw new Error('Authentication required.');
  }
  return actor;
}
