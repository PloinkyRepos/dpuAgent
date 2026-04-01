# DS02 - Storage Architecture

## Summary

`dpuAgent` stores confidential state in a dedicated storage root. It separates metadata, ACL state, encrypted secret values, and confidential blob payloads so that each concern has an explicit file and lifecycle.

## Background / Problem Statement

Secrets and confidential objects have different persistence needs:

- object metadata must be queryable and sortable
- ACL state must be centrally normalized
- secret values must not appear in plaintext on disk
- concurrent writes must not corrupt storage

## Data Model

### `state.json`

`state.json` is the main metadata registry. It holds:

- `users`
- `secrets`
- `objects`
- `version`

Secret entries here do not store plaintext values. They store identifiers and ownership metadata only.

### `permissions.manifest.json`

The permissions manifest is the ACL source of truth. It stores:

- canonical principal identities
- alias buckets for identities
- per-secret ACL maps
- per-confidential-object ACL maps

### `secrets.json`

`secrets.json` stores the secret value map as one encrypted payload. The file is not JSON-in-plaintext; it is a versioned encrypted blob with the prefix `DPUSECS1`.

### `blobs/`

Confidential file bodies are stored separately from metadata. File content is encrypted and written to the blob path derived from the object id.

## Persistence Rules

1. Metadata writes go through `withLockedState()`.
2. `state.json` and `permissions.manifest.json` are written atomically via temp file + rename.
3. Secret values are read and written through `readSecretsMap()` and `writeEncryptedSecretMap()`.
4. Blob content is separate from metadata so listings do not require content reads.

## Locking Model

Storage writes use a directory lock `.lock` with retry and timeout semantics:

- lock acquisition retries for up to 8 seconds
- all stateful mutations happen inside the lock
- lock removal is best-effort in `finally`

This provides simple single-writer safety without an external database.

## Path Resolution

Storage root resolution is:

1. `DPU_DATA_ROOT`
2. default to `path.join(path.dirname(workspaceRoot), '.dpu-storage')`

Workspace root resolution is:

1. `DPU_WORKSPACE_ROOT`
2. `ASSISTOS_FS_ROOT`
3. `WORKSPACE_ROOT`
4. `process.cwd()`

## Failure Semantics

- missing storage files are treated as empty/default state
- malformed encrypted secret storage is rejected as invalid
- missing `DPU_MASTER_KEY` is a hard error
- lock timeout is a hard error

