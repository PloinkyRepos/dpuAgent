# Agents Working Guide

## Canonical links

The canonical HTML documentation entry point is [dpuAgent/docs/index.html](./dpuAgent/docs/index.html).

The full documentation folder is [dpuAgent/docs](./dpuAgent/docs/).

The design specifications folder is [dpuAgent/docs/specs](./dpuAgent/docs/specs/).

## Language policy

All documentation and specifications must be written in English.

## HTML documentation style rules

The HTML documentation must use a technical writing style with minimal code examples.

The content should explain the repository around `dpuAgent` as an intermediary layer between Explorer/UI systems and DPU runtime capabilities. It should document MCP exposure, tool contracts, plugin roles, identity-aware ACL behavior, and integration flow in operational terms.

## Specification writing rules

Specifications must always include `DS01` and `DS02` as vision and architecture anchors for the current scope. Additional DS files are added only when needed by scope.

Specifications must focus on rules, constraints, and invariants. The emphasis is on what the Ploinky agent must do, independent of implementation details or historical steps used to reach the outcome.

Specifications should avoid excessive bullet-list formatting. Narrative, requirement-style sections are preferred when possible.

Specifications must keep the same agent story as the HTML docs, but from an agent-contract perspective. `dpuAgent` must remain defined as the intermediary between Explorer confidential UX and DPU storage/runtime behavior.

## Change management requirement

Any code change must be reflected in the HTML documentation under `dpuAgent/docs`, in the specifications under `dpuAgent/docs/specs`, and validated by running `npm test` in `dpuAgent/`.
