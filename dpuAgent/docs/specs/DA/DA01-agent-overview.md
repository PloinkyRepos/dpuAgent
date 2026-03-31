# DA01 - DPU Agent Overview

## Summary

`dpuAgent` este agentul MCP pentru stocare confidențială, secrete, obiecte binare și ACL-uri asociate.

## Background / Problem Statement

Explorer are nevoie de un backend separat pentru resurse confidențiale. Datele și permisiunile nu trebuie modelate ca fișiere obișnuite din filesystem.

## Goals

1. Să gestioneze storage confidențial separat de filesystem
2. Să aplice ACL-uri și identity rules
3. Să expună contracte MCP clare pentru Explorer

## Architecture Overview

| Area | Responsibility |
|---|---|
| `server/standalone-mcp-server.mjs` | runtime standalone |
| `lib/dpu-store*.mjs` | persistare, secrete, obiecte, ACL |
| `tests/` | testele pentru store și contracte |

## API Contracts

Agentul deservește capabilități pentru:

- secret storage
- confidential object listing și read/write
- comment/state adjunct logic folosită de Explorer
- permissions manifest și identity resolution

## Configuration

Variabile relevante:

- `DPU_MASTER_KEY`
- `DPU_DATA_ROOT`
- `DPU_WORKSPACE_ROOT`
- `ASSISTOS_FS_ROOT`
- `WORKSPACE_ROOT`

## Explorer Integration

Explorer consumă `dpuAgent` pentru:

- ruta `/Confidential`
- listing de obiecte și secrete
- metadata și capabilități pe path
- flows de comentarii și OnlyOffice pentru obiecte suportate
