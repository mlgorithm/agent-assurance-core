# Agent Assurance — core specification

**Version 1 (`evidence.v1`). Status: draft.**

This is the language-neutral specification for the agent-assurance kernel: the data
shapes and algorithms that every implementation and every distribution (firewall,
control plane, benchmark, embedded monitor) MUST share so their decisions and
evidence interoperate. The Rust crate in this repository is the **reference
implementation**; this document is the source of truth.

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in RFC 2119.

## 1. Scope

The kernel answers exactly one question — *may this proposed action proceed?* — and
emits tamper-evident evidence of what it answered. It does **not** define transports,
execution, orchestration, or policy authoring. Those belong to adapters and
distributions and are out of scope.

A conformant system has three roles; an implementation MAY provide any subset:

- **Decision engine** — maps a `ProposedAction` to a `Decision`.
- **Evidence emitter** — writes `evidence.v1` records into a hash-chained, optionally
  signed audit log.
- **Verifier** — recomputes the chain and checks signatures.

## 2. ProposedAction (decision input)

A normalized description of an action an agent intends to take. Adapters (MCP, HTTP,
stdio, framework hooks, an actuator command) MUST map their input onto this shape; the
engine MUST NOT depend on any transport detail.

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | string | yes | `"agent-assurance.evidence.v1"` |
| `action_type` | string | yes | e.g. `"tool_call"` |
| `name` | string | yes | tool / actuator command name |
| `arguments` | any (JSON) | yes | call arguments |
| `agent` | string\|null | no | caller identity, if known |
| `session_id` | string\|null | no | correlation id |
| `resource` | string\|null | no | target resource, if applicable |
| `transport` | string\|null | no | informational only; never affects the decision |

## 3. Decision and decision labels

`decide(action) -> Decision`. A `Decision` is one of:

- `Allow` — the action may proceed.
- `Block { reason, rules }` — the action MUST NOT proceed.
- `RequireApproval { reason, rules }` — the action MUST be held for an out-of-band
  human/operator decision before it may proceed.

A decision engine MUST be **deterministic** and MUST perform no I/O (no network, disk,
or clock) while deciding. The same `ProposedAction` and policy MUST always yield the
same `Decision`.

Evidence records carry a **decision label** string. The label is derived from the
`Decision`, the engine's mode (`enforce` | `observe`), and — for held actions — the
approval outcome:

| Decision | Mode | Approval outcome | Label |
|---|---|---|---|
| Allow | enforce/observe | — | `allow` |
| Block | enforce | — | `block` |
| Block | observe | — | `would_block` |
| RequireApproval | enforce | (pending) | `require_approval` |
| RequireApproval | observe | — | `would_require_approval` |
| RequireApproval | enforce | approved | `approved` |
| RequireApproval | enforce | denied | `denied` |
| RequireApproval | enforce | timed out | `timeout` |
| (any, forwarded leg) | — | — | `observe` |

A conformant emitter MUST use exactly these label strings.

## 4. Evidence record (`evidence.v1`)

The unit of evidence. Its JSON Schema is [`schema/evidence-v1.schema.json`](schema/evidence-v1.schema.json)
(JSON Schema draft 2020-12) and is normative; the table below is informative.

| Field | Type | Required |
|---|---|---|
| `schema_version` | const `"agent-assurance.evidence.v1"` | yes |
| `ts` | string (RFC3339) | yes |
| `type` | string | yes |
| `direction` | `"request"` \| `"response"` \| `"event"` | yes |
| `decision` | decision label (§3) | yes |
| `session_id`, `agent`, `reason` | string\|null | no |
| `tool` | `{ name, arguments }` \| null | no |
| `result` | `{ is_error, summary }` \| null | no |
| `latency_ms` | integer\|null | no |
| `context` | object\|null | no — **distribution-specific** fields live here |

Transport- and distribution-specific fields (e.g. the MCP/HTTP proxy's `rpc_id`,
`method`, `transport`, `client_addr`, `upstream`) MUST NOT be added as top-level
fields; they go in `context`. This keeps one record shape valid for cloud software and
embedded actuators alike. Emitters MUST produce records that validate against the
schema (`additionalProperties` is `false`).

## 5. Audit chain

Records are appended to a log as **entries**. Each entry is one line:

```
{ "seq": <u64>, "prev": <hex>, "hash": <hex>, "sig": <hex|absent>, "record": <record JSON> }
```

- `record` is the exact serialized bytes of the evidence record. Verifiers MUST hash
  the **stored bytes**, not a re-serialization.
- **Link hash:** `hash = lowercase_hex( sha256( hex_decode(prev) || record_bytes ) )`,
  where `||` is byte concatenation and `record_bytes` is the UTF-8 of the stored
  `record`. The first entry's `prev` is the **genesis** value: 32 zero bytes, hex
  (64 `0`s). Golden vectors: [`conformance/hash-vectors.json`](conformance/hash-vectors.json).
- **Sequence:** `seq` starts at 1 and increments by 1; entry *n*'s `prev` MUST equal
  entry *n−1*'s `hash` (entry 1's `prev` is genesis).
- **Signature (optional):** when signing, `sig` is an Ed25519 (RFC 8032) signature over
  the UTF-8 bytes of the lowercase-hex `hash` string, by the log's signing key.
  Ed25519's own RFC 8032 test vectors govern signature conformance.

**Verification.** A verifier MUST, from genesis: check `seq` continuity, check
`prev` equals the previous `hash`, recompute the link hash over the stored
`record_bytes` and check it equals `hash`, and (when a public key is supplied) check
`sig`. Any failure means the log is invalid; a verifier MUST report the first failing
entry. A tampered `record`, a forged/absent signature, a wrong key, a gap in `seq`, or
a broken `prev` link MUST all fail. When an **expected head** is supplied (§5.1), a log
that does not reach it — truncated or diverged — MUST also fail.

### 5.1 Head anchoring and truncation (additive in v1)

A hash chain proves that no entry was altered, inserted, or reordered. But **a prefix of
a valid chain is itself a valid chain**, so deleting entries from the *end* (truncation),
or deleting the whole log, **cannot be detected from the log in isolation** — the
remainder still verifies. Detection requires an out-of-band reference held in a
**different trust domain** from the writer.

The terminal entry's `hash` commits, through the chain, to the entire log up to that
point, and in a signed log it is itself signed. The pair **`head = { seq, hash }`** is
therefore a compact, self-authenticating checkpoint of the whole prefix. A **witness**
(e.g. a control plane) that retains the latest `head` it has received can later detect
truncation of any copy of the log presented to it.

A verifier MAY accept an **expected head**. When supplied, in addition to the checks
above it MUST confirm the log contains an entry at `seq == head.seq` whose
`hash == head.hash`, and MUST fail otherwise — specifically when the log is shorter than
`head.seq` (truncated) or its entry at `head.seq` differs (diverged). A log **longer**
than `head.seq` is acceptable provided the entry at `head.seq` matches: the head is a
high-water mark, not an end marker. A verifier SHOULD expose the terminal `head` of any
log it accepts, so the caller can persist it as the next expected head.

**Trust model (informative).** Signed-mode verification is tamper-evident only against an
adversary that does **not** hold the signing key: such an adversary cannot alter or forge
a record without breaking a signature. It does **not** defend against a holder of the key
(e.g. a fully compromised host) rebuilding the log, nor — absent an expected head —
against truncation. Unsigned verification (no public key) detects only accidental
corruption, because the hash chain is keyless and anyone can recompute it: **signed mode
is REQUIRED for any tamper-evidence claim.** Where the threat model includes host
compromise, keep the signing key in a separate trust domain (HSM / TPM / remote signer)
and anchor the `head` with an independent witness.

## 6. Conformance

- A conformant **emitter** MUST emit records that validate against the schema, use the
  §3 labels, and chain per §5.
- A conformant **verifier** MUST implement §5 verification and agree with the verifier
  conformance cases.
- A conformant **decision engine** MUST be deterministic and side-effect free (§3).

Conformance fixtures live in [`conformance/`](conformance/): `hash-vectors.json`
(link-hash golden values), `evidence-records.json` (records that MUST validate or
MUST be rejected), and `verify-vectors.json` (whole-log `verify` outcomes: a valid
signed log, plus tampered, forged-signature, reordered, and truncated-against-a-head
cases that MUST be rejected). Implementations in any language SHOULD run these.

## 7. Versioning

`evidence.v1` is frozen once published except for additive, backward-compatible
clarifications. Breaking changes MUST bump the schema id to `evidence.v2`. The
`schema_version` field lets consumers route by version. Head-anchored verification and
the `head` output (§5.1) are **additive**: the record shape and the link hash are
unchanged, and a verifier given no expected head behaves exactly as before.

## 8. Non-normative: how the kernel is meant to be used

The kernel is called *before* an action: an adapter builds a `ProposedAction`, the
engine decides, the host honors the decision and executes/refuses/holds, and the
emitter writes the evidence. The kernel decides and witnesses; it never acts. Adapters
and deployment modes (embedded library, sidecar/proxy, gateway, offline verifier,
certified physical monitor) are distributions on top of this core.
