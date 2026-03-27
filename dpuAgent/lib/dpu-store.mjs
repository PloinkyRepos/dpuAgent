import fs from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

import {
  canonicalizePrincipal,
  isNonEmptyString,
  normalizeName,
  normalizePathSegment,
  normalizePrincipal,
  normalizeSecretKey,
  nowIso
} from './dpu-store-internal/common.mjs';
import {
  CONFIDENTIAL_ROLE_ORDER,
  SECRET_ROLE_ORDER,
  aclEntries,
  confidentialRoleAllows,
  normalizeCommentRecords,
  pickMaxRole,
  requireAuthenticatedActor,
  resolveActor,
  secretRoleAllows,
  serializeConfidentialComments
} from './dpu-store-internal/identity-acl.mjs';
import {
  deleteSecretsFileValue,
  decryptConfidentialContent,
  ensureFileParentExists,
  encryptConfidentialContent,
  fileExists,
  getConfidentialBlobPath,
  loadState,
  loadPermissionsManifest,
  readSecretsMap,
  removePathIfExists,
  saveState,
  savePermissionsManifest,
  upsertSecretsFileValue,
  withFileLock
} from './dpu-store-internal/storage.mjs';
import {
  deletePermissionEntry,
  extractIdentityHints,
  getPermissionAcl,
  removePermissionRole,
  resolvePrincipalReference,
  setPermissionRole,
  upsertPrincipalIdentity
} from './dpu-store-internal/permissions-manifest.mjs';

export { resolveActor };

async function writeEncryptedConfidentialFile(objectRecord, content) {
  const blobPath = getConfidentialBlobPath(objectRecord.id);
  await ensureFileParentExists(blobPath);
  const encrypted = encryptConfidentialContent(content);
  await fs.writeFile(blobPath, encrypted, 'utf8');
}

async function writeConfidentialFile(objectRecord, content) {
  await writeEncryptedConfidentialFile(objectRecord, String(content ?? ''));
}

async function readConfidentialFile(objectRecord) {
  const blobPath = getConfidentialBlobPath(objectRecord.id);
  if (!(await fileExists(blobPath))) {
    throw new Error(`Confidential file storage is missing for object ${objectRecord.id || ''}`.trim());
  }
  const raw = await fs.readFile(blobPath, 'utf8');

  const decrypted = decryptConfidentialContent(raw);
  if (decrypted !== null) {
    return decrypted;
  }
  throw new Error(`Confidential file storage is invalid for object ${objectRecord.id || ''}`.trim());
}

function getSecret(state, key) {
  const normalizedKey = normalizeSecretKey(key);
  return state.secrets[normalizedKey] || null;
}

function getConfidentialObject(state, id) {
  const normalizedId = normalizeName(id, 'id');
  return state.objects[normalizedId] || null;
}

function getConfidentialAncestors(state, objectRecord) {
  const chain = [];
  const seen = new Set();
  let current = objectRecord;
  while (current && !seen.has(current.id)) {
    seen.add(current.id);
    chain.push(current);
    current = current.parentId ? state.objects[current.parentId] || null : null;
  }
  return chain;
}

function getSecretAclMap(secret, permissionsManifest) {
  return getPermissionAcl(permissionsManifest, 'secret', secret?.key || '') || {};
}

function getConfidentialAclMap(objectRecord, permissionsManifest) {
  return getPermissionAcl(permissionsManifest, 'confidential', objectRecord?.id || '') || {};
}

function buildActorPrincipalCandidates(actorOrPrincipal) {
  const values = [];
  const pushValue = (value) => {
    const normalized = canonicalizePrincipal(value);
    if (normalized && !values.includes(normalized)) {
      values.push(normalized);
    }
  };

  if (actorOrPrincipal && typeof actorOrPrincipal === 'object') {
    pushValue(actorOrPrincipal.principalId);
    pushValue(actorOrPrincipal.email);
    pushValue(actorOrPrincipal.id);
    pushValue(actorOrPrincipal.username);
    if (isNonEmptyString(actorOrPrincipal.id)) {
      pushValue(`user:${actorOrPrincipal.id}`);
    }
    if (isNonEmptyString(actorOrPrincipal.username)) {
      pushValue(`user:${actorOrPrincipal.username}`);
    }
    if (isNonEmptyString(actorOrPrincipal.ssoSubject)) {
      pushValue(`sso:${actorOrPrincipal.ssoSubject}`);
    }
    return values;
  }

  pushValue(actorOrPrincipal);
  return values;
}

function buildPrincipalReferenceCandidates(principal, permissionsManifest) {
  const values = [];
  const pushValue = (value) => {
    const normalized = canonicalizePrincipal(value);
    if (normalized && !values.includes(normalized)) {
      values.push(normalized);
    }
  };

  const normalizedPrincipal = normalizePrincipal(principal, 'principal');
  pushValue(normalizedPrincipal);

  const resolvedPrincipal = resolvePrincipalReference(permissionsManifest, normalizedPrincipal);
  pushValue(resolvedPrincipal);

  for (const value of [...values]) {
    const localMatch = value.match(/^user:local:(.+)$/i);
    if (localMatch && isNonEmptyString(localMatch[1])) {
      pushValue(localMatch[1].trim());
    }
  }

  return values;
}

function getSecretRole(secret, actorOrPrincipal, permissionsManifest) {
  const normalizedPrincipalId = actorOrPrincipal && typeof actorOrPrincipal === 'object'
    ? canonicalizePrincipal(actorOrPrincipal.principalId)
    : canonicalizePrincipal(actorOrPrincipal);
  if (!secret || !normalizedPrincipalId) return null;
  if (secret.ownerId === normalizedPrincipalId) return 'write';
  const aclMap = getSecretAclMap(secret, permissionsManifest);
  const matchedRoles = buildActorPrincipalCandidates(actorOrPrincipal)
    .map((principal) => aclMap?.[principal])
    .filter((role) => isNonEmptyString(role));
  return pickMaxRole(matchedRoles, SECRET_ROLE_ORDER);
}

function getConfidentialRole(state, objectRecord, actorOrPrincipal, permissionsManifest) {
  const normalizedPrincipalId = actorOrPrincipal && typeof actorOrPrincipal === 'object'
    ? canonicalizePrincipal(actorOrPrincipal.principalId)
    : canonicalizePrincipal(actorOrPrincipal);
  if (!objectRecord || !normalizedPrincipalId) return null;
  const principalCandidates = buildActorPrincipalCandidates(actorOrPrincipal);
  const candidates = [];
  for (const current of getConfidentialAncestors(state, objectRecord)) {
    if (current.ownerId === normalizedPrincipalId) {
      candidates.push('write');
    }
    const aclMap = getConfidentialAclMap(current, permissionsManifest);
    for (const principal of principalCandidates) {
      if (isNonEmptyString(aclMap?.[principal])) {
        candidates.push(aclMap[principal]);
      }
    }
  }
  return pickMaxRole(candidates, CONFIDENTIAL_ROLE_ORDER);
}

function assertSecretPermission(secret, actor, permission, permissionsManifest) {
  const role = getSecretRole(secret, actor, permissionsManifest);
  if (!role || !secretRoleAllows(role, permission)) {
    throw new Error(`Access denied: missing ${permission} on secret ${secret?.key || ''}`.trim());
  }
  return role;
}

function assertConfidentialPermission(state, objectRecord, actor, permission, permissionsManifest) {
  const role = getConfidentialRole(state, objectRecord, actor, permissionsManifest);
  if (!role || !confidentialRoleAllows(role, permission)) {
    throw new Error(`Access denied: missing ${permission} on confidential object ${objectRecord?.id || ''}`.trim());
  }
  return role;
}

function ensureUniqueSiblingName(state, parentId, name, excludedId = '') {
  const normalizedName = normalizePathSegment(name, 'name');
  const sibling = Object.values(state.objects).find((entry) => (
    entry
    && entry.parentId === parentId
    && entry.id !== excludedId
    && String(entry.name || '') === normalizedName
  ));
  if (sibling) {
    throw new Error(`An object named "${normalizedName}" already exists in this folder.`);
  }
  return normalizedName;
}

function collectChildObjects(state, parentId) {
  return Object.values(state.objects).filter((item) => item && item.parentId === parentId);
}

function collectSharedObjects(state, permissionsManifest, actor) {
  return Object.values(state.objects).filter((item) => {
    if (!item || item.ownerId === actor.principalId) return false;
    const directRole = getConfidentialRole(state, item, actor, permissionsManifest);
    return Boolean(directRole && confidentialRoleAllows(directRole, 'access'));
  });
}

function sortByName(items) {
  return [...items].sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
}

function isSystemRootObject(objectRecord) {
  return objectRecord?.type === 'folder' && objectRecord?.parentId === null && objectRecord?.name === 'My Space';
}

async function deleteObjectRecursive(state, rootId) {
  const children = collectChildObjects(state, rootId);
  for (const child of children) {
    await deleteObjectRecursive(state, child.id);
  }
  const current = state.objects[rootId];
  if (current?.type === 'file') {
    await removePathIfExists(getConfidentialBlobPath(current.id));
  }
  delete state.objects[rootId];
}

async function ensureUserRecord(state, permissionsManifest, actor, ctx) {
  const principalId = actor.principalId;
  const existing = state.users[principalId] && typeof state.users[principalId] === 'object'
    ? state.users[principalId]
    : null;
  const timestamp = nowIso();
  const next = existing || {
    principalId,
    privateId: randomUUID(),
    createdAt: timestamp
  };
  if (!isNonEmptyString(next.privateId)) {
    next.privateId = randomUUID();
    ctx.dirty = true;
  }
  const desiredRootId = next.privateId;
  const previousRootId = isNonEmptyString(next.mySpaceRootId) ? next.mySpaceRootId : desiredRootId;
  if (previousRootId !== desiredRootId) {
    const previousRoot = state.objects[previousRootId];
    if (previousRoot && typeof previousRoot === 'object') {
      state.objects[desiredRootId] = {
        ...previousRoot,
        id: desiredRootId
      };
      delete state.objects[previousRootId];
      for (const objectRecord of Object.values(state.objects)) {
        if (objectRecord?.parentId === previousRootId) {
          objectRecord.parentId = desiredRootId;
        }
      }
    }
    ctx.dirty = true;
  }
  next.mySpaceRootId = desiredRootId;
  next.updatedAt = timestamp;
  next.username = actor.username || next.username || '';
  next.email = actor.email || next.email || '';
  next.ssoSubject = actor.ssoSubject || next.ssoSubject || '';

  const currentRoot = state.objects[next.mySpaceRootId];
  if (!currentRoot || typeof currentRoot !== 'object') {
    state.objects[next.mySpaceRootId] = {
      id: next.mySpaceRootId,
      type: 'folder',
      name: 'My Space',
      parentId: null,
      ownerId: principalId,
      acl: {},
      comments: [],
      mimeType: '',
      createdAt: timestamp,
      updatedAt: timestamp
    };
    ctx.dirty = true;
  } else {
    if (currentRoot.ownerId !== principalId) {
      currentRoot.ownerId = principalId;
      ctx.dirty = true;
    }
    if (!Array.isArray(currentRoot.comments)) {
      currentRoot.comments = [];
      ctx.dirty = true;
    }
  }

  if (!existing) {
    state.users[principalId] = next;
    ctx.dirty = true;
  } else {
    state.users[principalId] = next;
  }

  if (upsertPrincipalIdentity(permissionsManifest, principalId, extractIdentityHints({ user: {
    email: actor.email,
    username: actor.username,
    id: actor.id,
    sub: actor.ssoSubject,
    roles: actor.roles,
    claims: actor.claims
  }, issuer: actor.issuer }))) {
    ctx.permissionsDirty = true;
  }

  return next;
}

async function withLockedState(worker) {
  return withFileLock(async () => {
    const state = await loadState();
    const permissionsManifest = await loadPermissionsManifest();
    const ctx = { dirty: false, permissionsDirty: false };
    const result = await worker(state, permissionsManifest, ctx);
    if (ctx.dirty) {
      await saveState(state);
    }
    if (ctx.permissionsDirty) {
      await savePermissionsManifest(permissionsManifest);
    }
    return result;
  });
}

async function serializeSecret(state, permissionsManifest, secret, actor, options = {}) {
  const includeValue = options.includeValue !== false;
  const role = getSecretRole(secret, actor, permissionsManifest);
  const canRead = Boolean(role && secretRoleAllows(role, 'read'));
  const canWrite = Boolean(role && secretRoleAllows(role, 'write'));
  const aclVisible = canWrite;
  let value = null;
  if (includeValue && canRead) {
    const secretsMap = await readSecretsMap();
    value = Object.prototype.hasOwnProperty.call(secretsMap, secret.key)
      ? secretsMap[secret.key]
      : null;
  }
  return {
    id: secret.id,
    key: secret.key,
    ownerId: secret.ownerId,
    role,
    canRead,
    canWrite,
    valueVisible: includeValue && canRead,
    value,
    valueMasked: includeValue && !canRead,
    aclVisible,
    acl: aclVisible ? aclEntries(getSecretAclMap(secret, permissionsManifest)) : [],
    createdAt: secret.createdAt,
    updatedAt: secret.updatedAt
  };
}

async function serializeConfidentialObject(state, permissionsManifest, objectRecord, actor, options = {}) {
  const includeContent = options.includeContent === true;
  const role = getConfidentialRole(state, objectRecord, actor, permissionsManifest);
  const canRead = Boolean(role && confidentialRoleAllows(role, 'read'));
  const canComment = Boolean(role && confidentialRoleAllows(role, 'comment'));
  const canWrite = Boolean(role && confidentialRoleAllows(role, 'write'));
  const aclVisible = canWrite;
  const commentsVisible = Boolean(includeContent && canRead);
  const comments = commentsVisible
    ? serializeConfidentialComments(objectRecord, actor, canWrite, nowIso)
    : [];
  let content = null;
  if (includeContent && objectRecord.type === 'file' && canRead) {
    content = await readConfidentialFile(objectRecord);
  }
  return {
    id: objectRecord.id,
    type: objectRecord.type,
    name: objectRecord.name,
    parentId: objectRecord.parentId || null,
    ownerId: objectRecord.ownerId,
    mimeType: objectRecord.mimeType || '',
    role,
    canRead,
    canComment,
    canWrite,
    contentVisible: includeContent && objectRecord.type === 'file' ? canRead : false,
    content,
    commentsVisible,
    commentCount: normalizeCommentRecords(objectRecord.comments, nowIso).length,
    comments,
    aclVisible,
    acl: aclVisible ? aclEntries(getConfidentialAclMap(objectRecord, permissionsManifest)) : [],
    createdAt: objectRecord.createdAt,
    updatedAt: objectRecord.updatedAt
  };
}

export async function getWhoAmI(authInfo = null) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = resolveActor(authInfo, permissionsManifest);
    if (!actor.authenticated) {
      return {
        ok: true,
        authenticated: false,
        actor: {
          principalId: '',
          email: '',
          username: '',
          id: '',
          roles: []
        },
        userSpace: null
      };
    }
    const userSpace = await ensureUserRecord(state, permissionsManifest, actor, ctx);
    return {
      ok: true,
      authenticated: true,
      actor: {
        principalId: actor.principalId,
        email: actor.email,
        username: actor.username,
        id: actor.id,
        roles: actor.roles
      },
      userSpace: {
        privateId: userSpace.privateId,
        mySpaceRootId: userSpace.mySpaceRootId
      }
    };
  });
}

export async function getWorkspaceRoots(authInfo = null) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    const userSpace = await ensureUserRecord(state, permissionsManifest, actor, ctx);
    return {
      ok: true,
      roots: {
        confidential: {
          path: '/Confidential',
          type: 'virtual-root'
        },
        mySpace: {
          id: userSpace.mySpaceRootId,
          path: '/Confidential/My Space',
          type: 'folder'
        },
        sharedFiles: {
          scope: 'shared',
          path: '/Confidential/Shared',
          type: 'virtual-list'
        },
        secrets: {
          scope: 'secrets',
          path: '/Confidential/Secrets',
          type: 'virtual-list'
        }
      }
    };
  });
}

export async function listSecrets(authInfo = null) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const secrets = [];
    for (const secret of Object.values(state.secrets)) {
      const role = getSecretRole(secret, actor, permissionsManifest);
      if (!role || !secretRoleAllows(role, 'access')) {
        continue;
      }
      secrets.push(await serializeSecret(state, permissionsManifest, secret, actor));
    }
    secrets.sort((a, b) => a.key.localeCompare(b.key));
    return { ok: true, secrets };
  });
}

export async function getSecretByKey(authInfo = null, { key }) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const secret = getSecret(state, key);
    if (!secret) {
      return { ok: false, error: `Secret not found: ${key}` };
    }
    assertSecretPermission(secret, actor, 'access', permissionsManifest);
    return { ok: true, secret: await serializeSecret(state, permissionsManifest, secret, actor) };
  });
}

export async function putSecret(authInfo = null, { key, value }) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const normalizedKey = normalizeSecretKey(key);
    const normalizedValue = String(value ?? '');
    let secret = getSecret(state, normalizedKey);
    if (secret) {
      assertSecretPermission(secret, actor, 'write', permissionsManifest);
      secret.updatedAt = nowIso();
    } else {
      secret = {
        id: randomUUID(),
        key: normalizedKey,
        ownerId: actor.principalId,
        acl: {},
        createdAt: nowIso(),
        updatedAt: nowIso()
      };
      state.secrets[normalizedKey] = secret;
      ctx.dirty = true;
    }
    await upsertSecretsFileValue(normalizedKey, normalizedValue);
    secret.updatedAt = nowIso();
    ctx.dirty = true;
    return { ok: true, secret: await serializeSecret(state, permissionsManifest, secret, actor) };
  });
}

export async function deleteSecret(authInfo = null, { key }) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const secret = getSecret(state, key);
    if (!secret) {
      return { ok: false, error: `Secret not found: ${key}` };
    }
    assertSecretPermission(secret, actor, 'write', permissionsManifest);
    delete state.secrets[secret.key];
    if (deletePermissionEntry(permissionsManifest, 'secret', secret.key)) {
      ctx.permissionsDirty = true;
    }
    await deleteSecretsFileValue(secret.key);
    ctx.dirty = true;
    return { ok: true, deleted: true, key: secret.key };
  });
}

export async function grantSecret(authInfo = null, { key, principal, role }) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const secret = getSecret(state, key);
    if (!secret) {
      return { ok: false, error: `Secret not found: ${key}` };
    }
    if (secret.ownerId !== actor.principalId) {
      throw new Error('Only the secret owner can manage ACL.');
    }
    const normalizedRole = normalizeName(role, 'role').toLowerCase();
    if (!SECRET_ROLE_ORDER.includes(normalizedRole)) {
      throw new Error('Invalid secret role.');
    }
    const normalizedPrincipal = resolvePrincipalReference(
      permissionsManifest,
      normalizePrincipal(principal, 'principal')
    );
    if (normalizedPrincipal !== secret.ownerId) {
      setPermissionRole(permissionsManifest, 'secret', secret.key, normalizedPrincipal, normalizedRole);
      secret.updatedAt = nowIso();
      ctx.dirty = true;
      ctx.permissionsDirty = true;
    }
    return { ok: true, secret: await serializeSecret(state, permissionsManifest, secret, actor) };
  });
}

export async function revokeSecret(authInfo = null, { key, principal }) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const secret = getSecret(state, key);
    if (!secret) {
      return { ok: false, error: `Secret not found: ${key}` };
    }
    if (secret.ownerId !== actor.principalId) {
      throw new Error('Only the secret owner can manage ACL.');
    }
    const principalCandidates = buildPrincipalReferenceCandidates(principal, permissionsManifest);
    const changed = principalCandidates.reduce((didChange, candidate) => {
      return removePermissionRole(permissionsManifest, 'secret', secret.key, candidate) || didChange;
    }, false);
    if (changed) {
      secret.updatedAt = nowIso();
      ctx.dirty = true;
      ctx.permissionsDirty = true;
    }
    return { ok: true, secret: await serializeSecret(state, permissionsManifest, secret, actor) };
  });
}

export async function listConfidential(authInfo = null, { scope = 'my-space', parentId = '' } = {}) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    const userSpace = await ensureUserRecord(state, permissionsManifest, actor, ctx);

    if (scope === 'shared') {
      const items = [];
      for (const item of sortByName(collectSharedObjects(state, permissionsManifest, actor))) {
        items.push(await serializeConfidentialObject(state, permissionsManifest, item, actor, { includeContent: false }));
      }
      return { ok: true, scope: 'shared', items };
    }

    const resolvedParentId = isNonEmptyString(parentId) ? parentId.trim() : userSpace.mySpaceRootId;
    const parent = getConfidentialObject(state, resolvedParentId);
    if (!parent) {
      return { ok: false, error: `Confidential object not found: ${resolvedParentId}` };
    }
    assertConfidentialPermission(state, parent, actor, 'access', permissionsManifest);
    const items = [];
    for (const item of sortByName(collectChildObjects(state, resolvedParentId))) {
      const role = getConfidentialRole(state, item, actor, permissionsManifest);
      if (!role || !confidentialRoleAllows(role, 'access')) {
        continue;
      }
      items.push(await serializeConfidentialObject(state, permissionsManifest, item, actor, { includeContent: false }));
    }
    return {
      ok: true,
      scope: 'my-space',
      parent: await serializeConfidentialObject(state, permissionsManifest, parent, actor, { includeContent: false }),
      items
    };
  });
}

export async function getConfidentialById(authInfo = null, { id }) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const objectRecord = getConfidentialObject(state, id);
    if (!objectRecord) {
      return { ok: false, error: `Confidential object not found: ${id}` };
    }
    assertConfidentialPermission(state, objectRecord, actor, 'access', permissionsManifest);
    return {
      ok: true,
      object: await serializeConfidentialObject(state, permissionsManifest, objectRecord, actor, { includeContent: true })
    };
  });
}

export async function createConfidential(authInfo = null, payload = {}) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    const userSpace = await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const type = normalizeName(payload.type, 'type').toLowerCase();
    if (!['file', 'folder'].includes(type)) {
      throw new Error('type must be "file" or "folder".');
    }
    const parentId = isNonEmptyString(payload.parentId) ? payload.parentId.trim() : userSpace.mySpaceRootId;
    const parent = getConfidentialObject(state, parentId);
    if (!parent) {
      return { ok: false, error: `Parent object not found: ${parentId}` };
    }
    if (parent.type !== 'folder') {
      throw new Error('Parent must be a folder.');
    }
    assertConfidentialPermission(state, parent, actor, 'write', permissionsManifest);
    const name = ensureUniqueSiblingName(state, parent.id, payload.name);

    const objectRecord = {
      id: randomUUID(),
      type,
      name,
      parentId: parent.id,
      ownerId: parent.ownerId,
      acl: {},
      comments: [],
      mimeType: type === 'file' ? String(payload.mimeType || '').trim() : '',
      createdAt: nowIso(),
      updatedAt: nowIso()
    };
    state.objects[objectRecord.id] = objectRecord;

    if (type === 'file') {
      await writeConfidentialFile(objectRecord, payload.content || '');
    }
    ctx.dirty = true;
    return {
      ok: true,
      object: await serializeConfidentialObject(state, permissionsManifest, objectRecord, actor, { includeContent: true })
    };
  });
}

export async function updateConfidential(authInfo = null, payload = {}) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const objectRecord = getConfidentialObject(state, payload.id);
    if (!objectRecord) {
      return { ok: false, error: `Confidential object not found: ${payload.id}` };
    }
    if (isSystemRootObject(objectRecord)) {
      throw new Error('My Space root cannot be renamed or edited directly.');
    }
    assertConfidentialPermission(state, objectRecord, actor, 'write', permissionsManifest);

    if (Object.prototype.hasOwnProperty.call(payload, 'name') && isNonEmptyString(payload.name)) {
      const nextName = ensureUniqueSiblingName(state, objectRecord.parentId || null, payload.name, objectRecord.id);
      if (nextName !== objectRecord.name) {
        objectRecord.name = nextName;
        ctx.dirty = true;
      }
    }

    if (objectRecord.type === 'file') {
      if (Object.prototype.hasOwnProperty.call(payload, 'content')) {
        await writeConfidentialFile(objectRecord, payload.content ?? '');
      }
      if (Object.prototype.hasOwnProperty.call(payload, 'mimeType')) {
        objectRecord.mimeType = String(payload.mimeType || '').trim();
        ctx.dirty = true;
      }
    }

    objectRecord.updatedAt = nowIso();
    ctx.dirty = true;
    return {
      ok: true,
      object: await serializeConfidentialObject(state, permissionsManifest, objectRecord, actor, { includeContent: true })
    };
  });
}

export async function deleteConfidential(authInfo = null, { id }) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const objectRecord = getConfidentialObject(state, id);
    if (!objectRecord) {
      return { ok: false, error: `Confidential object not found: ${id}` };
    }
    if (isSystemRootObject(objectRecord)) {
      throw new Error('My Space root cannot be deleted.');
    }
    assertConfidentialPermission(state, objectRecord, actor, 'write', permissionsManifest);
    await deleteObjectRecursive(state, objectRecord.id);
    if (deletePermissionEntry(permissionsManifest, 'confidential', objectRecord.id)) {
      ctx.permissionsDirty = true;
    }
    ctx.dirty = true;
    return { ok: true, deleted: true, id: objectRecord.id };
  });
}

export async function grantConfidential(authInfo = null, { id, principal, role }) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const objectRecord = getConfidentialObject(state, id);
    if (!objectRecord) {
      return { ok: false, error: `Confidential object not found: ${id}` };
    }
    if (isSystemRootObject(objectRecord)) {
      throw new Error('My Space root cannot be shared directly.');
    }
    if (objectRecord.ownerId !== actor.principalId) {
      throw new Error('Only the object owner can manage ACL.');
    }
    const normalizedRole = normalizeName(role, 'role').toLowerCase();
    if (!CONFIDENTIAL_ROLE_ORDER.includes(normalizedRole)) {
      throw new Error('Invalid confidential role.');
    }
    const normalizedPrincipal = resolvePrincipalReference(
      permissionsManifest,
      normalizePrincipal(principal, 'principal')
    );
    if (normalizedPrincipal !== objectRecord.ownerId) {
      setPermissionRole(permissionsManifest, 'confidential', objectRecord.id, normalizedPrincipal, normalizedRole);
      objectRecord.updatedAt = nowIso();
      ctx.dirty = true;
      ctx.permissionsDirty = true;
    }
    return {
      ok: true,
      object: await serializeConfidentialObject(state, permissionsManifest, objectRecord, actor, { includeContent: false })
    };
  });
}

export async function revokeConfidential(authInfo = null, { id, principal }) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const objectRecord = getConfidentialObject(state, id);
    if (!objectRecord) {
      return { ok: false, error: `Confidential object not found: ${id}` };
    }
    if (isSystemRootObject(objectRecord)) {
      throw new Error('My Space root cannot be shared directly.');
    }
    if (objectRecord.ownerId !== actor.principalId) {
      throw new Error('Only the object owner can manage ACL.');
    }
    const principalCandidates = buildPrincipalReferenceCandidates(principal, permissionsManifest);
    const changed = principalCandidates.reduce((didChange, candidate) => {
      return removePermissionRole(permissionsManifest, 'confidential', objectRecord.id, candidate) || didChange;
    }, false);
    if (changed) {
      objectRecord.updatedAt = nowIso();
      ctx.dirty = true;
      ctx.permissionsDirty = true;
    }
    return {
      ok: true,
      object: await serializeConfidentialObject(state, permissionsManifest, objectRecord, actor, { includeContent: false })
    };
  });
}

export async function addConfidentialComment(authInfo = null, { id, message }) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const objectRecord = getConfidentialObject(state, id);
    if (!objectRecord) {
      return { ok: false, error: `Confidential object not found: ${id}` };
    }
    assertConfidentialPermission(state, objectRecord, actor, 'comment', permissionsManifest);
    const normalizedMessage = normalizeName(message, 'comment message');
    objectRecord.comments = normalizeCommentRecords(objectRecord.comments, nowIso);
    const comment = {
      id: randomUUID(),
      authorPrincipal: actor.principalId,
      userEmail: actor.email || actor.principalId,
      message: normalizedMessage,
      createdAt: nowIso(),
      updatedAt: nowIso()
    };
    objectRecord.comments.push(comment);
    objectRecord.updatedAt = nowIso();
    ctx.dirty = true;
    return {
      ok: true,
      comment: serializeConfidentialComments({ comments: [comment] }, actor, true, nowIso)[0],
      object: await serializeConfidentialObject(state, permissionsManifest, objectRecord, actor, { includeContent: false })
    };
  });
}

export async function deleteConfidentialComment(authInfo = null, { id, commentId }) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const objectRecord = getConfidentialObject(state, id);
    if (!objectRecord) {
      return { ok: false, error: `Confidential object not found: ${id}` };
    }
    const role = assertConfidentialPermission(state, objectRecord, actor, 'comment', permissionsManifest);
    const normalizedCommentId = normalizeName(commentId, 'comment id');
    const comments = normalizeCommentRecords(objectRecord.comments, nowIso);
    const commentIndex = comments.findIndex((entry) => entry.id === normalizedCommentId);
    if (commentIndex < 0) {
      return { ok: false, error: `Confidential comment not found: ${commentId}` };
    }
    const canDeleteAnyComments = confidentialRoleAllows(role, 'write');
    if (!canDeleteAnyComments && comments[commentIndex].authorPrincipal !== actor.principalId) {
      throw new Error('Only the comment author or an editor can delete this comment.');
    }
    comments.splice(commentIndex, 1);
    objectRecord.comments = comments;
    objectRecord.updatedAt = nowIso();
    ctx.dirty = true;
    return {
      ok: true,
      deleted: true,
      commentId: normalizedCommentId,
      object: await serializeConfidentialObject(state, permissionsManifest, objectRecord, actor, { includeContent: false })
    };
  });
}

export async function accessCheck(authInfo = null, { kind, key, id, permission }) {
  return withLockedState(async (state, permissionsManifest, ctx) => {
    const actor = requireAuthenticatedActor(authInfo, permissionsManifest);
    await ensureUserRecord(state, permissionsManifest, actor, ctx);
    const normalizedKind = normalizeName(kind, 'kind').toLowerCase();
    const normalizedPermission = normalizeName(permission, 'permission').toLowerCase();

    if (normalizedKind === 'secret') {
      const secret = getSecret(state, key);
      if (!secret) {
        return { ok: false, error: `Secret not found: ${key}` };
      }
      const role = getSecretRole(secret, actor, permissionsManifest);
      const allowed = Boolean(role && secretRoleAllows(role, normalizedPermission));
      return {
        ok: true,
        kind: 'secret',
        allowed,
        effectiveRole: role,
        permission: normalizedPermission,
        resource: { key: secret.key, id: secret.id }
      };
    }

    if (normalizedKind === 'confidential') {
      const objectRecord = getConfidentialObject(state, id);
      if (!objectRecord) {
        return { ok: false, error: `Confidential object not found: ${id}` };
      }
      const role = getConfidentialRole(state, objectRecord, actor, permissionsManifest);
      const allowed = Boolean(role && confidentialRoleAllows(role, normalizedPermission));
      return {
        ok: true,
        kind: 'confidential',
        allowed,
        effectiveRole: role,
        permission: normalizedPermission,
        resource: { id: objectRecord.id, type: objectRecord.type, name: objectRecord.name }
      };
    }

    throw new Error('kind must be "secret" or "confidential".');
  });
}
