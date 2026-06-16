# Conformance vectors

Language-neutral fixtures that define what it means to implement `evidence.v1`
correctly (see [`../SPEC.md`](../SPEC.md)). Any implementation, in any language, can
run these against its own code to prove conformance.

| File | Tests |
|---|---|
| `hash-vectors.json` | the audit link-hash function: `sha256(hex_decode(prev) ‖ record_bytes)`. Every implementation MUST reproduce `expected_hash`. |
| `evidence-records.json` | records that MUST validate (`valid:true`) or MUST be rejected (`valid:false`) against [`../schema/evidence-v1.schema.json`](../schema/evidence-v1.schema.json). |
| `verify-vectors.json` | whole-log `verify` outcomes (SPEC.md §5–§5.1): a valid signed log; chain-only verification; and tampered, forged-signature, reordered, and truncated-against-an-anchored-head logs that MUST be rejected. |

`verify-vectors.json` is signed with a fixed, test-only key (embedded as `signing_key_hex`)
so the bytes are reproducible; regenerate with `cargo run --example gen_verify_vectors`.
Signature conformance is otherwise governed by Ed25519 (RFC 8032) over the lowercase-hex
`hash` string; use the RFC's own test vectors.

## Running them

- **Reference (Rust):** `cargo test --test conformance` in this crate.
- **Other languages:** load the JSON, recompute the hash / validate against the schema,
  and assert agreement. The fixtures are plain data on purpose.

These vectors are the gravity well of the standard: re-implement the kernel if you
like, but it must pass these.
