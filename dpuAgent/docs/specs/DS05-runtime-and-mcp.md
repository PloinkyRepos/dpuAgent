# DS05 - Runtime and MCP Interface

## Summary

`dpuAgent` exposes its domain through MCP tools defined in `mcp-config.json`. It can run as a standalone HTTP MCP server or under the Ploinky runtime, where Explorer and plugins call it through `callAgentTool(...)`.

## Runtime Modes

### Ploinky runtime

Under Ploinky, the agent receives environment variables from the manifest profile and is started as an MCP-capable service available to Explorer.

### Standalone runtime

The standalone entry point is:

`node ./server/standalone-mcp-server.mjs`

It serves:

- `POST /mcp`
- `GET /health`

## Tool Dispatch

`mcp-config.json` declares tools that all delegate into `tools/dpu_tool.sh` / `tools/dpu_tool.mjs`.

Dispatch flow:

1. MCP runtime resolves the tool entry
2. tool wrapper sets `TOOL_NAME`
3. stdin JSON envelope is parsed
4. auth metadata is extracted
5. normalized args are validated
6. corresponding function in `lib/dpu-store.mjs` is executed

## Auth Context

The tool layer extracts actor context from `metadata.authInfo`. That context is then normalized by the permissions manifest layer to resolve:

- principal id
- email
- username
- user id
- SSO subject
- issuer
- roles and claims

This is the basis for all ACL decisions.

## Tool Surface

Major groups:

- actor identity: `dpu_whoami`, `dpu_workspace_roots`
- secrets: `dpu_secret_list`, `dpu_secret_get`, `dpu_secret_put`, `dpu_secret_delete`, `dpu_secret_grant`, `dpu_secret_revoke`
- confidential objects: `dpu_confidential_list`, `dpu_confidential_get`, `dpu_confidential_create`, `dpu_confidential_update`, `dpu_confidential_delete`
- comments: `dpu_confidential_comment_add`, `dpu_confidential_comment_delete`
- permission checks: `dpu_access_check`

## Input Validation

Validation happens before domain execution:

- required string fields are enforced per tool
- secret keys must pass secret-key normalization
- enum-like fields are explicitly constrained
- unsupported tool names fail immediately

## Behavioral Guarantees

- all mutating operations are serialized through the storage lock
- unauthorized reads fail before plaintext secret or confidential content is materialized
- tool responses are actor-filtered, not raw storage dumps

