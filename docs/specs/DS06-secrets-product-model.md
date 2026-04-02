# DS06 - Secrets Product Model

## Summary

`dpuAgent` secrets should behave like a secure product surface, not like regular editable files, while still preserving the Explorer contract for `/Confidential/Secrets`. The target model emphasizes strong sensitivity handling, explicit management actions, and permission-driven visibility.

## Background / Problem Statement

The current DPU secret domain already has encrypted at-rest storage and ACL-aware reads, but the product model needs to be more explicit:

- secrets should be treated as sensitive runtime values
- creation and update flows should be distinct from ordinary file editing
- visibility should be permission-driven, not implied by presence in the list
- management UI should clearly separate value access from ACL management

At the same time, existing Explorer requirements must remain intact.

## Preserved Requirements

The following behavior is mandatory and remains part of the contract:

- `/Confidential/Secrets` is a virtual view rendered as a file-like list
- each listed item represents one secret
- if the actor has `read`, the actor can view the secret value
- if the actor has `write`, the actor can update the secret value
- secret permissions must be inspectable, including the list of entities that currently hold rights on that secret

## Explorer Representation

In Explorer, each secret is rendered as a file-like item in the tree and list under `/Confidential/Secrets`.

This representation must remain stable:

- the displayed item name is the secret `key`
- the secret `key` is the Explorer-visible file-like name
- the secret `value` is the managed content behind that item
- the item is not a real filesystem file and must not use generic filesystem persistence semantics

## Product Principles

The DPU secret product model should adopt these principles:

1. Secrets are managed objects, not normal documents.
2. Secret values are sensitive by default and should not be revealed accidentally.
3. Value update is a dedicated action, not a generic text-editing flow.
4. ACL management is a first-class management surface.
5. Metadata listing and value access are separate concerns.

## Domain-Specific Behavior

- DPU supports a true `read` role that may reveal the plaintext value.
- DPU supports a separate `access` role for operational use without plaintext disclosure.
- DPU renders secrets inside `/Confidential/Secrets`, which remains a virtual file-like Explorer surface.
- Value visibility is controlled and deliberate, but not globally forbidden after creation.
- Secret entries may appear in list form like files, but they are still domain records, not filesystem files.

## Product Semantics

### Secret list behavior

`/Confidential/Secrets` should behave like a virtual file list with secret-specific semantics:

- name column maps to the secret key
- item type is logically `secret`
- selection opens a secret-aware details/view panel
- management actions are exposed as secret actions

### Create behavior

Inside `/Confidential/Secrets`, `New file` creates a new secret record:

- the entered file name becomes the secret `key`
- the created secret starts with an empty or explicitly provided initial `value`
- saving the opened item persists the secret `value`

Inside `/Confidential/Secrets`, `New folder` is not supported and must be disabled.

### Secret detail behavior

The secret details experience should expose:

- key
- owner
- actor role
- whether the value is visible to the current actor
- permissions/ACL list
- actions available for the actor

### Value visibility rules

- `access` only: no plaintext value
- `read`: plaintext value may be revealed
- `write`: plaintext value may be revealed and updated

The UI should default to safe presentation even when value visibility is allowed. Reveal should be deliberate, not implicit from simple listing.

## Update Semantics

If an actor has `write`:

- the actor may update the current secret value
- the update becomes the new live value immediately
- all runtime consumers with operational `access` observe the new value on their next resolution/use path

The update action should be modeled as `set secret value`. Explorer may expose this through the standard `Edit` / `Save` controls, but persistence must resolve to the secret API, not to filesystem writes.

Before persisting a value update, Explorer should re-check the current secret revision metadata. If the secret changed after the current actor entered edit mode, the save must be rejected and the latest server version must be reloaded before the actor can retry.

## ACL Visibility and Management

The actor must be able to inspect which principals have rights on a secret, subject to DPU permission policy.

The management surface should distinguish:

- owner
- principals with `access`
- principals with `read`
- principals with `write`

For owners or authorized writers, grant and revoke remain first-class actions.

## Explorer UX Requirements

Explorer integration for `/Confidential/Secrets` should follow these rules:

1. The list stays file-like for consistency with the rest of Explorer.
2. Opening a secret routes to a secret-aware preview that shows key, owner, role, and value visibility state.
   The secret key remains the Explorer-visible item name and preview title; the preview card should prioritize operational metadata such as owner, created time, and updated time.
3. Actions should include the secret-oriented equivalents of:
   - create secret
   - update
   - delete
   - inspect permissions
   - grant
   - revoke
4. Secret values should never be written back through filesystem save flows. Any save operation must resolve to the DPU secret API.
5. `New folder` must be hidden or disabled for `/Confidential/Secrets`.
6. Rename should not be treated as a normal filesystem rename unless DPU later defines an explicit secret-key rename contract.

## API and Contract Implications

The existing MCP tools remain valid as the backend contract:

- `dpu_secret_list`
- `dpu_secret_get`
- `dpu_secret_put`
- `dpu_secret_delete`
- `dpu_secret_grant`
- `dpu_secret_revoke`

The frontend/product shift is primarily semantic and UX-facing:

- `dpu_secret_put` becomes the backing operation for create/update value
- `dpu_secret_get` becomes the backing operation for reveal/details
- `dpu_secret_list` becomes the backing operation for the virtual secrets list

## Non-Goals

- removing plaintext read capability for actors with explicit `read`
- representing secrets as real files in the workspace filesystem
