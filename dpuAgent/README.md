# DPU Agent

Standalone MCP agent for:

- encrypted secret storage
- confidential file and folder management
- object and secret ACL enforcement
- identity resolution through a central permissions manifest

## Standalone runtime

The repo can run without Ploinky through:

```bash
npm install
DPU_MASTER_KEY=... DPU_DATA_ROOT=... node ./server/standalone-mcp-server.mjs
```

Environment variables:

- `DPU_MASTER_KEY`: required master key for encrypted storage
- `DPU_DATA_ROOT`: optional storage root for state, permissions manifest, blobs, and encrypted secrets
- `DPU_WORKSPACE_ROOT`: optional logical workspace root

Default HTTP endpoint:

- `POST /mcp`
- `GET /health`
