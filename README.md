# agent-assurance-core

The shared action-assurance kernel — the **reference implementation** and home of the
**`evidence.v1` standard** ([`SPEC.md`](SPEC.md)) for agent action assurance. Apache-2.0.

This crate contains the stable primitives that every distribution shares:

- policy decisions: `Allow`, `Block`, `RequireApproval`
- normalized proposed actions
- versioned evidence records
- hash-chained audit entries
- Ed25519 signing and verification

Product-specific transports stay outside this crate. `agent-firewall` adapts MCP,
HTTP, and stdio into this kernel. `agent-firewall-cloud` verifies the same audit
entry format. `agent-crash-lab` emits deterministic benchmark evidence with the
same `agent-assurance.evidence.v1` schema.

The kernel is called *before* an action: an adapter builds a `ProposedAction`, the
engine decides (`Allow` / `Block` / `RequireApproval`), the host honors it, and the
emitter writes a signed, hash-chained `evidence.v1` record. **The kernel decides and
witnesses; it never acts.** Keep it small and pure — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Specification & conformance

- [`SPEC.md`](SPEC.md) — the normative, language-neutral spec (proposed action,
  decision + labels, evidence record, audit-chain hash + signature).
- [`schema/evidence-v1.schema.json`](schema/evidence-v1.schema.json) — the evidence-record JSON Schema.
- [`conformance/`](conformance/) — language-neutral fixtures any implementation runs to
  prove conformance.

```sh
cargo test                      # lib tests + conformance vectors
cargo test --test conformance   # just the conformance suite
```

## Bindings (C ABI / WASM)

The same core is callable from C/C++, Python, embedded targets, and — via `wasm32` —
JavaScript. The portable surface is evidence hashing + verification. See
[`bindings/`](bindings/) (`cargo build && python3 bindings/ffi_ctypes.py`).

## Project

- [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`GOVERNANCE.md`](GOVERNANCE.md) ·
  [`SECURITY.md`](SECURITY.md) · [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) ·
  [`MAINTAINERS.md`](MAINTAINERS.md)
- License: **Apache-2.0** ([`LICENSE`](LICENSE)).
