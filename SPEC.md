# Agent Assurance — core specification

**Version 1 — `evidence.v1` + `receipt.v1`. Status: draft.**

This is the language-neutral specification for the agent-assurance kernel: the data
shapes and algorithms that every implementation and every distribution (firewall,
control plane, benchmark, embedded monitor) MUST share so their decisions and
evidence interoperate. The Rust crate in this repository is the **reference
implementation**; this document is the source of truth.

The kernel treats the agent as an **untrusted process** and a tool call as its
"syscall": it mediates each proposed action, decides under an explicit policy and
capability model, and emits a provenance-typed, tamper-evident receipt. It does
not certify that an agent is safe; it certifies that an *execution* was mediated,
bounded, and recorded under a stated trust model (§9–§10).

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

## 4a. Assurance Receipt (`receipt.v1`)

The evidence record says *what happened*. An **Assurance Receipt** says, for one
mediated action, *what was checked, and how much each claim can be trusted*. Its
JSON Schema is [`schema/agent-assurance.receipt.v1.json`](schema/agent-assurance.receipt.v1.json).

Receipt fields are grouped **strictly by provenance**, because not all evidence
warrants the same trust:

| Group | Provenance | Trust |
|---|---|---|
| `fact` | independently verifiable | trust no one — recompute it (content hashes, tool invoked, policy digest, chain head/`seq`) |
| `attested` | a component's verdict | trust *iff* you trust that component and its key (policy decision, capability check, monitor verdict, risk budget) |
| `claimed` | agent self-report | **untrusted** — recorded for context only (e.g. declared `intent`) |

An emitter MUST place each field in the group matching its provenance. In
particular, anything the agent reports about *itself* MUST be `claimed` — never
`fact` or `attested`. A receipt is embedded in the evidence record `context`, so
it inherits the chain's tamper-evidence and head anchoring (§5).

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
`sig`. It MUST report the first failing entry. A tampered `record`, a
forged/absent signature, a wrong key, a gap in `seq`, or a broken `prev` link MUST
all fail.

The per-entry chain alone is **not sufficient** — a truncated *prefix* of a valid
log is itself a valid log, so the chain cannot detect tail truncation, rollback,
or a full wipe. A conformant verifier MUST therefore also enforce two whole-log
properties:

- **Non-empty.** An empty log (zero entries) MUST verify as **invalid** unless the
  caller explicitly opts in (`allow_empty`). Missing evidence is a failure signal,
  not a pass.
- **Head anchoring.** Given an out-of-band anchor `(seq_n, hash_n)` — the head a
  witness recorded as the log was produced — the verifier MUST check the log ends
  at exactly that anchor: the entry count equals `seq_n` **and** the final `hash`
  equals `hash_n`. Without an anchor, tail truncation/rollback/wipe are
  undetectable; with it, they fail.

The writer returns the head from each append; a control plane records the latest
head per log and supplies it as the anchor when it re-verifies. The anchor's
integrity rests on the witness, not on the log being checked. This is **Theorem 3**
(§9), and the one integrity guarantee this core establishes with no dependence on
the mediation assumption. Verifier conformance cases:
[`conformance/verify-vectors.json`](conformance/verify-vectors.json).

## 6. Conformance

- A conformant **emitter** MUST emit records that validate against the schema, use the
  §3 labels, and chain per §5.
- A conformant **verifier** MUST implement §5 verification and agree with the verifier
  conformance cases.
- A conformant **decision engine** MUST be deterministic and side-effect free (§3).

Conformance fixtures live in [`conformance/`](conformance/): `hash-vectors.json`
(link-hash golden values), `evidence-records.json` (records that MUST validate or
MUST be rejected), and `verify-vectors.json` (whole logs with options that a
verifier MUST accept or reject — pinning the empty-log and head-anchoring rules of
§5). Implementations in any language SHOULD run all three.

## 7. Versioning

`evidence.v1` is frozen once published except for additive, backward-compatible
clarifications. Breaking changes MUST bump the schema id to `evidence.v2`. The
`schema_version` field lets consumers route by version.

## 8. Non-normative: how the kernel is meant to be used

The kernel is called *before* an action: an adapter builds a `ProposedAction`, the
engine decides, the host honors the decision and executes/refuses/holds, and the
emitter writes the evidence. The kernel decides and witnesses; it never acts. Adapters
and deployment modes (embedded library, sidecar/proxy, gateway, offline verifier,
certified physical monitor) are distributions on top of this core.

## 9. Formal model and theorems

The kernel is the transition `K(s, a) -> (decision, s', receipt)`. Kernel state is
`s = { capabilities, risk_budget, policy, monitor, log_head, seq }`; an action `a`
is a `ProposedAction`; `decision ∈ {allow, deny, require_human_review}`. The
transition is deterministic and performs **no I/O** (the host supplies the
timestamp and appends the evidence).

**Soundness invariant.** The kernel MUST allow an action only when every clause
holds:

```
decision(a) = allow  ⇒  policy.allow(a)
                        ∧ required_capability(a) ∈ capabilities
                        ∧ monitor.accept(a)
                        ∧ risk_budget.affords(cost(a))
```

The reference kernel realizes this by fail-closed precedence (policy block,
missing capability, monitor reject → deny; policy approval, exhausted budget →
review; otherwise allow) and asserts it **biconditionally** as a property test.

Each theorem below holds **under explicitly stated assumptions**. The implication
itself is shallow; the engineering value is the *minimization and naming* of the
assumptions. The load-bearing one is **Assumption M (complete mediation)** — every
external action actually reaches the kernel — which the kernel does **not**
establish on its own (§10).

- **Theorem 1 (Enforcement Soundness).** If M holds and the kernel allows only
  when `policy.allow`, no policy-denied action reaches the tool layer. *(Also
  assumes policy is total/decidable; fail-closed on policy error.)*
- **Theorem 2 (Capability Safety).** If M holds and every tool action requires a
  held capability, an agent cannot act outside its capability set. This bounds
  *authority*, **not** *misuse of legitimate authority* — the confused-deputy /
  prompt-injection case is outside what capabilities can decide and falls to the
  monitor (empirical).
- **Theorem 3 (Trace Integrity).** Under a collision-resistant hash and a trusted
  head anchor, deletion, reordering, truncation, or wipe of accepted events is
  detectable (§5). **This is the only theorem the core establishes with no
  dependence on M**; it is enforced and regression-tested here.
- **Theorem 4 (Review-Gate Safety).** If M holds and policy marks an action class
  as requiring approval (or the budget is exhausted), the kernel denies it unless
  approval evidence exists; so no such action executes without review.

**Empirical assurance.** Properties the kernel cannot prove — monitor soundness,
prompt-injection resistance — are **not** theorems. They are measured
adversarially (`agent-crash-lab`) and reported as confidence bounds (e.g. *k
failures in n trials → ~95% upper bound 3/n at k = 0*). Formal assurance bounds
what the kernel enforces by construction; empirical assurance bounds the rest.
Neither yields "safe".

## 10. Trust model (TCB) and the mediation assumption

The agent is **not** in the trusted computing base. The TCB is deliberately small:

- **Trusted:** the kernel, the policy evaluator, the capability and budget
  accounting, the monitor implementation, the verifier, and the hash/anchor/key
  mechanism.
- **Untrusted:** the model, the prompt, the agent/planner, tool outputs,
  user-provided content, and the external environment.

**Complete mediation (Assumption M).** Every theorem that constrains *actions*
(1, 2, 4) assumes every external action is routed through the kernel. The kernel
is the syscall *filter*, not the privilege *ring*: nothing in this core stops an
agent process from egressing directly (opening its own socket, shelling out). M
MUST be discharged by a deployment boundary **outside this crate** — a sandbox /
network namespace / egress control whose only path out is the enforcing
distribution — and SHOULD be validated for a given deployment by an adversarial
mediation-bypass test (`agent-crash-lab`). A distribution that claims Theorem 1, 2,
or 4 without establishing M is making a decorative claim.

**Local signing is not proof against a compromised host.** A signature shows the
key-holder attested the head; a compromised signing host can re-sign a rewritten
chain. Local signatures protect evidence against parties *without* the key
(tampering after export, another tenant) — not against the signing host itself.
External, independent head witnessing (a transparency-log-style anchor) is what
closes that gap.

## 11. Assurance levels

Deployments are graded **AA-0…AA-5** by *what an independent party can verify*, not
by what the system does internally. See
[`ASSURANCE-LEVELS.md`](ASSURANCE-LEVELS.md).
