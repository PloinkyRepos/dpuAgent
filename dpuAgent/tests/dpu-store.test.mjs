import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const tempWorkspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dpu-store-workspace-'));
const tempDpuDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dpu-store-data-'));
const moduleSuffix = `?test=${Date.now()}`;
const storeUrl = new URL('../lib/dpu-store.mjs', import.meta.url);
const {
  addConfidentialComment,
  createConfidential,
  deleteConfidentialComment,
  getConfidentialById,
  getSecretByKey,
  getWhoAmI,
  grantSecret,
  grantConfidential,
  putSecret,
  resolveActor
} = await import(`${storeUrl.href}${moduleSuffix}`);

const previousWorkspaceRoot = process.env.DPU_WORKSPACE_ROOT;
const previousDpuDataRoot = process.env.DPU_DATA_ROOT;
const previousMasterKey = process.env.DPU_MASTER_KEY;

process.env.DPU_WORKSPACE_ROOT = tempWorkspaceDir;
process.env.DPU_DATA_ROOT = tempDpuDataDir;
process.env.DPU_MASTER_KEY = 'unit-test-master-key';

const authInfo = {
  user: {
    email: 'owner@example.com'
  }
};

async function getStoredObject(objectId) {
  const statePath = path.join(tempDpuDataDir, 'state.json');
  const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  return state.objects[objectId];
}

function getStoredState() {
  const statePath = path.join(tempDpuDataDir, 'state.json');
  return JSON.parse(fs.readFileSync(statePath, 'utf8'));
}

function setStoredState(state) {
  const statePath = path.join(tempDpuDataDir, 'state.json');
  fs.writeFileSync(statePath, JSON.stringify(state, null, 2), 'utf8');
}

function getBlobPath(objectId) {
  return path.join(tempDpuDataDir, 'blobs', objectId);
}

function getSecretsPath() {
  return path.join(tempDpuDataDir, 'secrets.json');
}

function getPermissionsManifestPath() {
  return path.join(tempDpuDataDir, 'permissions.manifest.json');
}

function getPermissionsManifest() {
  return JSON.parse(fs.readFileSync(getPermissionsManifestPath(), 'utf8'));
}

test.beforeEach(() => {
  fs.rmSync(tempWorkspaceDir, { recursive: true, force: true });
  fs.rmSync(tempDpuDataDir, { recursive: true, force: true });
  fs.mkdirSync(tempWorkspaceDir, { recursive: true });
  fs.mkdirSync(tempDpuDataDir, { recursive: true });
});

test.after(() => {
  if (previousWorkspaceRoot === undefined) {
    delete process.env.DPU_WORKSPACE_ROOT;
  } else {
    process.env.DPU_WORKSPACE_ROOT = previousWorkspaceRoot;
  }
  if (previousDpuDataRoot === undefined) {
    delete process.env.DPU_DATA_ROOT;
  } else {
    process.env.DPU_DATA_ROOT = previousDpuDataRoot;
  }
  if (previousMasterKey === undefined) {
    delete process.env.DPU_MASTER_KEY;
  } else {
    process.env.DPU_MASTER_KEY = previousMasterKey;
  }
  fs.rmSync(tempWorkspaceDir, { recursive: true, force: true });
  fs.rmSync(tempDpuDataDir, { recursive: true, force: true });
});

test('confidential files are encrypted at rest outside the workspace boundary', async () => {
  await getWhoAmI(authInfo);
  const created = await createConfidential(authInfo, {
    type: 'file',
    name: 'note.txt',
    content: 'top secret text',
    mimeType: 'text/plain'
  });
  assert.equal(created.ok, true);
  const objectRecord = await getStoredObject(created.object.id);
  const blobPath = getBlobPath(created.object.id);
  const rawOnDisk = fs.readFileSync(blobPath, 'utf8');

  assert.equal(objectRecord.storagePath, undefined);
  assert.equal(path.join(tempDpuDataDir, 'state.json').startsWith(`${tempWorkspaceDir}${path.sep}`), false);
  assert.equal(blobPath.startsWith(`${tempWorkspaceDir}${path.sep}`), false);
  assert.match(rawOnDisk, /^DPUENC1:/);
  assert.notEqual(rawOnDisk, 'top secret text');

  const fetched = await getConfidentialById(authInfo, { id: created.object.id });
  assert.equal(fetched.ok, true);
  assert.equal(fetched.object.content, 'top secret text');
});

test('secret values are encrypted at rest and remain readable through ACL-aware APIs', async () => {
  await putSecret(authInfo, { key: 'API_TOKEN', value: 'top-secret-value' });
  const rawOnDisk = fs.readFileSync(getSecretsPath(), 'utf8');

  assert.match(rawOnDisk, /^DPUSECS1:/);
  assert.equal(rawOnDisk.includes('top-secret-value'), false);

  const fetched = await getSecretByKey(authInfo, { key: 'API_TOKEN' });
  assert.equal(fetched.ok, true);
  assert.equal(fetched.secret.value, 'top-secret-value');
});

test('plaintext secret storage is rejected', async () => {
  await putSecret(authInfo, { key: 'LEGACY_TOKEN', value: 'legacy-value' });
  fs.writeFileSync(getSecretsPath(), 'LEGACY_TOKEN=legacy-value\n', 'utf8');
  await assert.rejects(
    () => getSecretByKey(authInfo, { key: 'LEGACY_TOKEN' }),
    /DPU secret storage is invalid/
  );
});

test('plaintext confidential storage is rejected', async () => {
  await getWhoAmI(authInfo);
  const created = await createConfidential(authInfo, {
    type: 'file',
    name: 'legacy.txt',
    content: '',
    mimeType: 'text/plain'
  });
  assert.equal(created.ok, true);
  const objectRecord = await getStoredObject(created.object.id);

  fs.writeFileSync(getBlobPath(objectRecord.id), 'legacy plaintext', 'utf8');
  const beforeRead = fs.readFileSync(getBlobPath(objectRecord.id), 'utf8');
  assert.equal(beforeRead, 'legacy plaintext');

  await assert.rejects(
    () => getConfidentialById(authInfo, { id: created.object.id }),
    /Confidential file storage is invalid/
  );
});

test('missing confidential blob is rejected', async () => {
  await getWhoAmI(authInfo);
  const created = await createConfidential(authInfo, {
    type: 'file',
    name: 'missing.txt',
    content: 'must exist',
    mimeType: 'text/plain'
  });
  assert.equal(created.ok, true);

  fs.rmSync(getBlobPath(created.object.id), { force: true });

  await assert.rejects(
    () => getConfidentialById(authInfo, { id: created.object.id }),
    /Confidential file storage is missing/
  );
});

test('resolveActor uses a single canonical principal with email priority', () => {
  const actor = resolveActor({
    user: {
      email: 'Reader@Example.com',
      id: 'reader-id',
      username: 'reader-user'
    }
  });

  assert.equal(actor.principalId, 'reader@example.com');
});

test('My Space root id is the user privateId', async () => {
  const whoami = await getWhoAmI(authInfo);
  assert.equal(whoami.ok, true);
  assert.equal(whoami.userSpace.mySpaceRootId, whoami.userSpace.privateId);

  const state = getStoredState();
  assert.ok(state.objects[whoami.userSpace.privateId]);
  assert.equal(state.objects[whoami.userSpace.privateId].name, 'My Space');
});

test('secret ACL principals are stored canonically and registry aliases keep the same principal across auth shapes', async () => {
  const ownerAuth = {
    user: {
      email: 'owner@example.com'
    }
  };
  const readerAuth = {
    user: {
      email: 'reader@example.com',
      id: 'reader-id',
      username: 'reader-user'
    }
  };
  const idOnlyAuth = {
    user: {
      id: 'reader-id',
      username: 'reader-user'
    }
  };

  await putSecret(ownerAuth, { key: 'CANONICAL_SECRET', value: 'value' });
  await grantSecret(ownerAuth, {
    key: 'CANONICAL_SECRET',
    principal: 'Reader@Example.com',
    role: 'read'
  });

  const manifest = getPermissionsManifest();
  assert.equal(manifest.permissions.secrets.CANONICAL_SECRET.acl['reader@example.com'], 'read');
  assert.equal(manifest.permissions.secrets.CANONICAL_SECRET.acl['Reader@Example.com'], undefined);

  const canonicalReader = await getSecretByKey(readerAuth, { key: 'CANONICAL_SECRET' });
  assert.equal(canonicalReader.ok, true);
  assert.equal(canonicalReader.secret.role, 'read');

  const idOnlyReader = await getSecretByKey(idOnlyAuth, { key: 'CANONICAL_SECRET' });
  assert.equal(idOnlyReader.ok, true);
  assert.equal(idOnlyReader.secret.role, 'read');
});

test('central permissions manifest becomes the ACL source of truth for secret access', async () => {
  const ownerAuth = {
    user: {
      email: 'owner@example.com'
    }
  };
  const readerAuth = {
    user: {
      email: 'reader@example.com'
    }
  };

  await putSecret(ownerAuth, { key: 'MANIFEST_SECRET', value: 'manifest-value' });
  await grantSecret(ownerAuth, {
    key: 'MANIFEST_SECRET',
    principal: 'reader@example.com',
    role: 'read'
  });

  const state = getStoredState();
  state.secrets.MANIFEST_SECRET.acl = {
    'reader@example.com': 'write'
  };
  setStoredState(state);

  const manifest = getPermissionsManifest();
  assert.equal(manifest.permissions.secrets.MANIFEST_SECRET.acl['reader@example.com'], 'read');

  const fetched = await getSecretByKey(readerAuth, { key: 'MANIFEST_SECRET' });
  assert.equal(fetched.ok, true);
  assert.equal(fetched.secret.role, 'read');
  assert.equal(fetched.secret.value, 'manifest-value');
});

test('identity registry can resolve principals from SSO claims without exposing email directly', async () => {
  const ownerAuth = {
    user: {
      email: 'registry-owner@example.com'
    }
  };
  await putSecret(ownerAuth, { key: 'SSO_SECRET', value: 'claims-value' });
  await grantSecret(ownerAuth, {
    key: 'SSO_SECRET',
    principal: 'registry-reader@example.com',
    role: 'read'
  });

  const manifest = getPermissionsManifest();
  manifest.identities.principals['registry-reader@example.com'] = {
    aliases: {
      emails: ['registry-reader@example.com'],
      userIds: ['reader-id'],
      usernames: [],
      ssoSubjects: ['oidc-reader-subject'],
      issuers: ['https://issuer.example.com']
    },
    claims: {
      roles: ['reader']
    },
    createdAt: '2026-03-27T00:00:00.000Z',
    updatedAt: '2026-03-27T00:00:00.000Z'
  };
  fs.writeFileSync(getPermissionsManifestPath(), JSON.stringify(manifest, null, 2), 'utf8');

  const ssoReader = await getSecretByKey({
    claims: {
      sub: 'oidc-reader-subject',
      iss: 'https://issuer.example.com',
      roles: ['reader']
    },
    user: {}
  }, { key: 'SSO_SECRET' });

  assert.equal(ssoReader.ok, true);
  assert.equal(ssoReader.secret.role, 'read');
  assert.equal(ssoReader.secret.value, 'claims-value');
});

test('comment role can add annotations without write access and read role can see them', async () => {
  const ownerAuth = {
    user: {
      email: 'owner@example.com'
    }
  };
  const commenterAuth = {
    user: {
      email: 'commenter@example.com'
    }
  };
  const readerAuth = {
    user: {
      email: 'reader@example.com'
    }
  };

  const created = await createConfidential(ownerAuth, {
    type: 'file',
    name: 'commentable.txt',
    content: 'shared text',
    mimeType: 'text/plain'
  });

  await grantConfidential(ownerAuth, {
    id: created.object.id,
    principal: 'commenter@example.com',
    role: 'comment'
  });
  await grantConfidential(ownerAuth, {
    id: created.object.id,
    principal: 'reader@example.com',
    role: 'read'
  });

  const commenterView = await getConfidentialById(commenterAuth, { id: created.object.id });
  assert.equal(commenterView.ok, true);
  assert.equal(commenterView.object.canRead, true);
  assert.equal(commenterView.object.canComment, true);
  assert.equal(commenterView.object.canWrite, false);

  const added = await addConfidentialComment(commenterAuth, {
    id: created.object.id,
    message: 'Please review this line.'
  });
  assert.equal(added.ok, true);
  assert.equal(added.comment.userEmail, 'commenter@example.com');

  await assert.rejects(
    () => addConfidentialComment(readerAuth, {
      id: created.object.id,
      message: 'I should not be able to comment.'
    }),
    /missing comment/
  );

  const readerView = await getConfidentialById(readerAuth, { id: created.object.id });
  assert.equal(readerView.ok, true);
  assert.equal(readerView.object.commentsVisible, true);
  assert.equal(readerView.object.commentCount, 1);
  assert.equal(readerView.object.comments[0].message, 'Please review this line.');
  assert.equal(readerView.object.comments[0].canDelete, false);

  await deleteConfidentialComment(commenterAuth, {
    id: created.object.id,
    commentId: added.comment.id
  });

  const ownerView = await getConfidentialById(ownerAuth, { id: created.object.id });
  assert.equal(ownerView.object.commentCount, 0);
});

test('existing confidential comments without a line remain readable as general comments', async () => {
  const ownerAuth = {
    user: {
      email: 'owner@example.com'
    }
  };

  const created = await createConfidential(ownerAuth, {
    type: 'file',
    name: 'legacy-comments.txt',
    content: 'hello',
    mimeType: 'text/plain'
  });

  const state = getStoredState();
  state.objects[created.object.id].comments = [{
    id: 'legacy-comment',
    authorPrincipal: 'owner@example.com',
    userEmail: 'owner@example.com',
    message: 'Older general comment.',
    createdAt: '2026-03-27T00:00:00.000Z',
    updatedAt: '2026-03-27T00:00:00.000Z'
  }];
  setStoredState(state);

  const ownerView = await getConfidentialById(ownerAuth, { id: created.object.id });
  assert.equal(ownerView.ok, true);
  assert.equal(ownerView.object.commentCount, 1);
  assert.equal(ownerView.object.comments[0].message, 'Older general comment.');
});
