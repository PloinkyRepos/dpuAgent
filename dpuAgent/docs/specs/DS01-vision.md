# DS01 - DPU Agent Vision and Goals

## Summary

`dpuAgent` is the confidential data plane for Explorer. It provides a separate storage and permissions model for secrets, confidential files, folders, comments, and identity-aware access control. It exists so confidential content is not modeled as normal workspace files and does not inherit regular filesystem semantics.

## Background / Problem Statement

Explorer needs to expose `/Confidential` as a protected logical workspace with capabilities that differ from the regular filesystem:

- encrypted secret storage
- confidential file and folder storage
- actor-aware ACL enforcement
- virtual roots such as `My Space`, `Shared with me`, and `Secrets`
- stable APIs for Explorer UI flows

Treating this data as ordinary files would blur ownership, permissions, and encryption boundaries.

## Goals

1. Provide a standalone MCP agent for confidential storage.
2. Keep secret values encrypted at rest.
3. Separate metadata, ACLs, and secret values into explicit layers.
4. Resolve actor identity consistently from auth context and claims.
5. Expose a small, stable tool surface for Explorer and related plugins.
6. Support both embedded Ploinky runtime and standalone local execution.

## Non-Goals

- General-purpose database features
- Filesystem mirroring of confidential state
- Public anonymous access
- Direct plaintext secret persistence on disk

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                           Explorer                            │
│    /Confidential UI, permissions modal, comments, previews    │
└──────────────────────────────┬───────────────────────────────┘
                               │ MCP tools
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                         dpuAgent                              │
│  tools/dpu_tool.mjs → lib/dpu-store.mjs → internal storage    │
└──────────────────────────────┬───────────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
┌─────────────────┐  ┌──────────────────────┐  ┌─────────────────┐
│ state.json       │  │ permissions.manifest │  │ secrets.json    │
│ metadata          │  │ ACL + identity map   │  │ encrypted values│
└─────────────────┘  └──────────────────────┘  └─────────────────┘
                               │
                               ▼
                      confidential blobs directory
```

## Component Responsibilities

| Component | Responsibility |
|-----------|----------------|
| `server/standalone-mcp-server.mjs` | standalone HTTP MCP runtime |
| `tools/dpu_tool.mjs` | MCP tool dispatch and auth envelope normalization |
| `lib/dpu-store.mjs` | domain logic for secrets, confidential objects, ACLs |
| `lib/dpu-store-internal/storage.mjs` | persistence, encryption, file locking |
| `lib/dpu-store-internal/permissions-manifest.mjs` | canonical principal and ACL model |
| `IDE-plugins/dpu-runtime-support` | Explorer UI integration for permissions/runtime flows |

## Configuration

| Variable | Description | Required |
|----------|-------------|----------|
| `DPU_MASTER_KEY` | master secret used to derive encryption keys | yes |
| `DPU_DATA_ROOT` | explicit storage root | no |
| `DPU_WORKSPACE_ROOT` | logical workspace root for resolution | no |
| `ASSISTOS_FS_ROOT` | workspace root fallback | no |
| `WORKSPACE_ROOT` | workspace root fallback | no |

## Directory Layout

By default, DPU storage lives under `../.dpu-storage` relative to the workspace root:

```
.dpu-storage/
├── state.json
├── permissions.manifest.json
├── secrets.json
├── blobs/
└── .lock/
```
