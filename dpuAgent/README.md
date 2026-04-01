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

## Documentation

- [DS01 - DPU Agent Vision and Goals](./docs/specs/DS01-vision.md)
- [DS02 - Storage Architecture](./docs/specs/DS02-storage-architecture.md)
- [DS03 - Secrets Model](./docs/specs/DS03-secrets-model.md)
- [DS04 - Confidential Objects and Collaboration Model](./docs/specs/DS04-confidential-objects.md)
- [DS05 - Runtime and MCP Interface](./docs/specs/DS05-runtime-and-mcp.md)
- [DS06 - Secrets Product Model](./docs/specs/DS06-secrets-product-model.md)
