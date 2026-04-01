# DS04 - Confidential Objects and Collaboration Model

## Summary

Confidential objects are the file and folder model behind `/Confidential`. They support ownership, ACLs, comments, separate blob storage, and actor-aware serialization for Explorer.

## Object Types

Supported object types:

- `folder`
- `file`

Objects are stored in `state.objects` and reference blob content by object id when the object is a file.

## Virtual Roots

For authenticated actors, the agent exposes:

- `/Confidential`
- `/Confidential/My Space`
- `/Confidential/Shared`
- `/Confidential/Secrets`

These are logical roots, not filesystem directories.

Explorer presents `/Confidential/Shared` with the user-facing label `Shared with me`.

## Confidential Roles

Confidential objects use a richer collaboration model than secrets. The serialized object exposes booleans such as:

- `canRead`
- `canComment`
- `canWrite`

This allows Explorer to drive editing, preview, comments, and permission UI without inferring capabilities client-side.

## Content Storage

For `file` objects:

- metadata lives in `state.objects`
- content lives in encrypted blob storage
- content is returned only when caller has read permission and requests content

For `folder` objects:

- metadata only
- no blob payload

## Comments

Comments are attached to confidential objects and serialized only when comments are visible to the actor. The agent supports comment add/delete flows and uses actor identity to evaluate authoring and permission constraints.

## Listing Modes

The confidential domain supports:

- actor-specific `My Space`
- shared listing
- nested listing by `parentId`

This lets Explorer render folder navigation and shared content views without exposing raw storage internals.

## ACL Management

ACL state for confidential objects lives in `permissions.manifest.json`, parallel to secrets. The object owner manages grants and revokes. Explorer surfaces this through the permissions modal plugin.

## Integration Notes

Explorer uses the confidential APIs for:

- `/Confidential` navigation
- permissions dialogs
- content fetch and update flows
- comments and collaboration affordances
