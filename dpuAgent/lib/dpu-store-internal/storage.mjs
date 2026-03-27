import fs from 'node:fs/promises';
import path from 'node:path';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

import {
  isNonEmptyString,
  sleep
} from './common.mjs';
import {
  defaultPermissionsManifest,
  normalizePermissionsManifest
} from './permissions-manifest.mjs';

const DPU_DATA_ROOT_NAME = '.dpu-storage';
const STATE_FILENAME = 'state.json';
const PERMISSIONS_MANIFEST_FILENAME = 'permissions.manifest.json';
const LOCK_DIRNAME = '.lock';
const BLOBS_DIRNAME = 'blobs';
const SECRETS_FILENAME = 'secrets.json';
const CONFIDENTIAL_FILE_PREFIX = 'DPUENC1';
const SECRET_MAP_FILE_PREFIX = 'DPUSECS1';
const CONFIDENTIAL_CONTEXT = 'dpu:confidential:';
const SECRET_MAP_CONTEXT = 'dpu:secret-map:';

export function getWorkspaceRoot() {
  const candidates = [
    process.env.DPU_WORKSPACE_ROOT,
    process.env.ASSISTOS_FS_ROOT,
    process.env.WORKSPACE_ROOT
  ].filter(isNonEmptyString);
  return path.resolve(candidates[0] || process.cwd());
}

export function getDpuDataRoot() {
  const configured = [
    process.env.DPU_DATA_ROOT
  ].find(isNonEmptyString);
  if (configured) {
    return path.resolve(configured);
  }
  return path.join(path.dirname(getWorkspaceRoot()), DPU_DATA_ROOT_NAME);
}

export function getStateFilePath() {
  return path.join(getDpuDataRoot(), STATE_FILENAME);
}

export function getLockDirPath() {
  return path.join(getDpuDataRoot(), LOCK_DIRNAME);
}

export function getPermissionsManifestPath() {
  return path.join(getDpuDataRoot(), PERMISSIONS_MANIFEST_FILENAME);
}

export function getSecretsFilePath() {
  return path.join(getDpuDataRoot(), SECRETS_FILENAME);
}

export function getConfidentialBlobsRoot() {
  return path.join(getDpuDataRoot(), BLOBS_DIRNAME);
}

export function getConfidentialBlobPath(objectId) {
  return path.join(getConfidentialBlobsRoot(), objectId);
}

function getConfiguredMasterKey() {
  const configured = [
    process.env.DPU_MASTER_KEY
  ].find((value) => String(value || '').trim());
  if (!configured) {
    throw new Error('DPU master key is not configured.');
  }
  return String(configured).trim();
}

function deriveMasterKey(namespace) {
  const configured = getConfiguredMasterKey();
  return createHash('sha256')
    .update(`${namespace}${configured}`, 'utf8')
    .digest();
}

export function getConfidentialMasterKey() {
  return deriveMasterKey(CONFIDENTIAL_CONTEXT);
}

export async function ensureParentDir(filePath) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
}

export async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

export async function readJsonFile(filePath, fallback) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : fallback;
  } catch {
    return fallback;
  }
}

export async function writeJsonFile(filePath, value) {
  await ensureParentDir(filePath);
  const tempPath = `${filePath}.tmp`;
  await fs.writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  await fs.rename(tempPath, filePath);
}

export async function withFileLock(task) {
  const lockDir = getLockDirPath();
  await ensureParentDir(lockDir);
  const timeoutMs = 8000;
  const startedAt = Date.now();
  while (true) {
    try {
      await fs.mkdir(lockDir);
      break;
    } catch (error) {
      if (error?.code !== 'EEXIST') {
        throw error;
      }
      if (Date.now() - startedAt > timeoutMs) {
        throw new Error('DPU store lock timeout.');
      }
      await sleep(50);
    }
  }
  try {
    return await task();
  } finally {
    await fs.rm(lockDir, { recursive: true, force: true }).catch(() => {});
  }
}

export function defaultState() {
  return {
    version: 3,
    users: {},
    secrets: {},
    objects: {}
  };
}

export async function loadState() {
  const state = await readJsonFile(getStateFilePath(), defaultState());
  return {
    version: Number(state.version || 3),
    users: state.users && typeof state.users === 'object' ? state.users : {},
    secrets: state.secrets && typeof state.secrets === 'object' ? state.secrets : {},
    objects: state.objects && typeof state.objects === 'object' ? state.objects : {}
  };
}

export async function saveState(state) {
  state.version = 3;
  await writeJsonFile(getStateFilePath(), state);
}

export async function loadPermissionsManifest() {
  const manifest = await readJsonFile(getPermissionsManifestPath(), defaultPermissionsManifest());
  return normalizePermissionsManifest(manifest);
}

export async function savePermissionsManifest(manifest) {
  await writeJsonFile(getPermissionsManifestPath(), normalizePermissionsManifest(manifest));
}

export async function readSecretsMap() {
  const filePath = getSecretsFilePath();
  if (!(await fileExists(filePath))) {
    return {};
  }
  const raw = await fs.readFile(filePath, 'utf8').catch(() => '');
  if (!raw.trim()) {
    return {};
  }
  const encrypted = parseEncryptedSecretMap(raw);
  if (!encrypted) {
    throw new Error('DPU secret storage is invalid.');
  }
  return encrypted;
}

export async function upsertSecretsFileValue(name, value) {
  const secrets = await readSecretsMap();
  secrets[name] = String(value ?? '');
  await writeEncryptedSecretMap(secrets);
}

export async function deleteSecretsFileValue(name) {
  const secrets = await readSecretsMap();
  if (!Object.prototype.hasOwnProperty.call(secrets, name)) {
    return;
  }
  delete secrets[name];
  await writeEncryptedSecretMap(secrets);
}

export async function removePathIfExists(targetPath) {
  if (await fileExists(targetPath)) {
    await fs.rm(targetPath, { recursive: true, force: true });
  }
}

export async function ensureFileParentExists(filePath) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
}

export function serializeEncryptedConfidentialPayload(iv, authTag, ciphertext) {
  return `${CONFIDENTIAL_FILE_PREFIX}:${iv.toString('base64')}:${authTag.toString('base64')}:${ciphertext.toString('base64')}`;
}

export function parseEncryptedConfidentialPayload(raw) {
  if (!isNonEmptyString(raw) || !raw.startsWith(`${CONFIDENTIAL_FILE_PREFIX}:`)) {
    return null;
  }
  const parts = raw.split(':');
  if (parts.length !== 4) {
    throw new Error('Confidential file payload is malformed.');
  }
  return {
    iv: Buffer.from(parts[1], 'base64'),
    authTag: Buffer.from(parts[2], 'base64'),
    ciphertext: Buffer.from(parts[3], 'base64')
  };
}

export function encryptConfidentialContent(content) {
  const key = getConfidentialMasterKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(String(content ?? ''), 'utf8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  return serializeEncryptedConfidentialPayload(iv, authTag, ciphertext);
}

export function decryptConfidentialContent(raw) {
  const payload = parseEncryptedConfidentialPayload(raw);
  if (!payload) {
    return null;
  }
  const key = deriveMasterKey(CONFIDENTIAL_CONTEXT);
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, payload.iv);
    decipher.setAuthTag(payload.authTag);
    const plaintext = Buffer.concat([
      decipher.update(payload.ciphertext),
      decipher.final()
    ]);
    return plaintext.toString('utf8');
  } catch {
    return null;
  }
}

function serializeEncryptedSecretMap(iv, authTag, ciphertext) {
  return `${SECRET_MAP_FILE_PREFIX}:${iv.toString('base64')}:${authTag.toString('base64')}:${ciphertext.toString('base64')}`;
}

function parseEncryptedSecretPayload(raw) {
  if (!isNonEmptyString(raw) || !raw.startsWith(`${SECRET_MAP_FILE_PREFIX}:`)) {
    return null;
  }
  const parts = raw.split(':');
  if (parts.length !== 4) {
    throw new Error('Encrypted DPU secrets payload is malformed.');
  }
  return {
    iv: Buffer.from(parts[1], 'base64'),
    authTag: Buffer.from(parts[2], 'base64'),
    ciphertext: Buffer.from(parts[3], 'base64')
  };
}

function encryptSecretMap(secretMap) {
  const key = deriveMasterKey(SECRET_MAP_CONTEXT);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(secretMap || {}), 'utf8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  return serializeEncryptedSecretMap(iv, authTag, ciphertext);
}

function parseEncryptedSecretMap(raw) {
  const payload = parseEncryptedSecretPayload(raw);
  if (!payload) {
    return null;
  }
  const key = deriveMasterKey(SECRET_MAP_CONTEXT);
  const decipher = createDecipheriv('aes-256-gcm', key, payload.iv);
  decipher.setAuthTag(payload.authTag);
  const plaintext = Buffer.concat([
    decipher.update(payload.ciphertext),
    decipher.final()
  ]).toString('utf8');
  const parsed = JSON.parse(plaintext);
  return parsed && typeof parsed === 'object' ? parsed : {};
}

async function writeEncryptedSecretMap(secretMap) {
  const filePath = getSecretsFilePath();
  await ensureParentDir(filePath);
  await fs.writeFile(filePath, encryptSecretMap(secretMap), 'utf8');
}
