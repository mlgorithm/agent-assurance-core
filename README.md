# agent-assurance-core

The shared action-assurance kernel — the **reference implementation** and home of the
**`evidence.v1` standard** ([`SPEC.md`](SPEC.md)) for agent action assurance. Apache-2.0.

This crate contains the stable primitives that every distribution shares:

- the kernel transition `K(s, a) -> (decision, s', receipt)` ([`kernel.rs`](src/kernel.rs))
- policy decisions: `Allow`, `Block`, `RequireApproval`
- **capability confinement** and a **depletable risk budget** (the provable parts of the model)
- a pluggable **monitor** seam (the empirical, attested part)
- normalized proposed actions and versioned evidence records
- **provenance-typed Assurance Receipts** (`fact` / `attested` / `claimed`)
- hash-chained audit entries with Ed25519 signing and **head-anchored, truncation-evident** verification

The model treats the agent as an **untrusted process** and a tool call as its
"syscall". The kernel allows an action only when policy allows *and* the capability
is held *and* the monitor accepts *and* the budget affords (the soundness
invariant, asserted as a property test). It does not certify that an agent is safe;
it certifies that an *execution* was mediated, bounded, and recorded under an
explicit trust model — see [`SPEC.md`](SPEC.md) §9–§10 and the AA-0…AA-5
[assurance levels](ASSURANCE-LEVELS.md).

Product-specific transports stay outside this crate. `agent-firewall` adapts MCP,
HTTP, and stdio into this kernel. `agent-firewall-cloud` witnesses heads and
re-verifies the same audit format. `agent-crash-lab` emits deterministic benchmark
evidence with the same `agent-assurance.evidence.v1` schema and is where the
mediation assumption and residual risk are tested.

The kernel is called *before* an action: an adapter builds a `ProposedAction`, the
kernel decides, the host honors it, and the emitter writes a signed, hash-chained
`evidence.v1` record carrying the receipt. **The kernel decides and witnesses; it
never acts.** It is deterministic and I/O-free — keep it small and pure; see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Specification & conformance

- [`SPEC.md`](SPEC.md) — the normative, language-neutral spec (proposed action,
  decision + labels, evidence record, receipt, audit-chain hash + signature,
  head anchoring, the formal model + four theorems, and the trust model / TCB).
- [`ASSURANCE-LEVELS.md`](ASSURANCE-LEVELS.md) — the AA-0…AA-5 levels, graded by
  what an independent party can verify.
- [`schema/evidence-v1.schema.json`](schema/evidence-v1.schema.json) and
  [`schema/agent-assurance.receipt.v1.json`](schema/agent-assurance.receipt.v1.json) — the JSON Schemas.
- [`conformance/`](conformance/) — language-neutral fixtures (hash vectors, evidence
  records, and verifier cases incl. truncation/empty) any implementation runs to
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
