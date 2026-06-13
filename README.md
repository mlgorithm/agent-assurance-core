# agent-assurance-core

The shared action-assurance kernel.

This crate contains the stable primitives that every distribution should share:

- policy decisions: `Allow`, `Block`, `RequireApproval`
- normalized proposed actions
- versioned evidence records
- hash-chained audit entries
- Ed25519 signing and verification

Product-specific transports stay outside this crate. `agent-firewall` adapts MCP,
HTTP, and stdio into this kernel. `agent-firewall-cloud` verifies the same audit
entry format. `agent-crash-lab` emits deterministic benchmark evidence with the
same `agent-assurance.evidence.v1` schema.
