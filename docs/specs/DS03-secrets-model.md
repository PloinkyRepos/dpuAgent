# DS03 - Secrets Model

## Summary

Secrets in `dpuAgent` are modeled as metadata plus encrypted value. The metadata lives in the main state and permissions manifest. The secret value lives in an encrypted map on disk and is only returned to callers with `read` permission.

## Goals

1. Keep plaintext secret values out of `state.json`.
2. Enforce secret ACLs through canonical principals.
3. Distinguish operational access from value visibility.
4. Use a storage format that can be validated and versioned.

## Secret Key Rules

Secret keys must match environment-variable style naming:

`^[A-Za-z_][A-Za-z0-9_]*$`

This keeps keys stable, explicit, and easy to reference from runtime integrations.

## Secret Roles

Secrets use three roles:

- `access`: actor can operationally reference the secret
- `read`: actor can view the secret value
- `write`: actor can update the value and manage ACL visibility

`write` implies ACL visibility. `read` implies value visibility. `access` does not imply plaintext disclosure.

## Storage Layout

### Metadata in `state.json`

Each secret entry stores:

- `id`
- `key`
- `ownerId`
- timestamps

### ACL in `permissions.manifest.json`

The manifest stores the canonical ACL map for each secret key.

### Encrypted values in `secrets.json`

The value map is encrypted as one payload using:

- AES-256-GCM
- per-write random IV
- auth tag
- key derived from `DPU_MASTER_KEY` with namespace `dpu:secret-map:`

## Write Flow

`putSecret()` does the following:

1. resolves the authenticated actor
2. ensures the actor has a user record
3. normalizes and validates the key
4. creates or updates metadata in `state.secrets`
5. writes the value through `upsertSecretsFileValue()`
6. returns a serialized secret filtered by actor permissions

## Read Flow

`getSecretByKey()` and `listSecrets()`:

1. resolve actor
2. evaluate role against manifest ACL
3. include plaintext value only when the actor has `read`
4. include ACL details only when the actor has `write`

## Delete Flow

`deleteSecret()` removes:

- metadata from `state.secrets`
- ACL entry from `permissions.manifest.json`
- value from encrypted `secrets.json`

## Security Properties

- no plaintext secret values in metadata files
- invalid plaintext `secrets.json` is rejected
- decryption requires `DPU_MASTER_KEY`
- permissions are enforced before value materialization

