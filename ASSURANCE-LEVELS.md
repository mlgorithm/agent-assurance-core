# Agent Assurance Levels (AA-0 … AA-5)

A vocabulary for *how much of an agent deployment an independent party can
verify*. Each level is defined by *what someone other than the operator can
check* — not by what the system claims to do internally. Higher levels cost more
and constrain more; pick the lowest one that covers your risk.

The levels deliberately track the §9 theorems and the §10 trust model in
[`SPEC.md`](SPEC.md): a level is only as high as the assumptions a third party can
actually confirm. "Fail closed on missing evidence" and "complete mediation" are
*not required* at the low levels — that is what keeps AA-1/AA-2 cheap enough for
development without pretending they are AA-3.

| Level | Name | Enforcement | Evidence | Independently verifiable claim |
|---|---|---|---|---|
| **AA-0** | None | none | none | nothing |
| **AA-1** | Logged | observe | schema-valid records | "these records are well-formed `evidence.v1`" |
| **AA-2** | Accounted | observe | provenance-typed receipts, hash-chained | "every action carries a policy decision + capability check, and the file is internally consistent" |
| **AA-3** | Enforced | enforce, fail-closed | signed + **head-anchored** chain, mediation established | "denied actions did not execute, and the log was not tampered or truncated" |
| **AA-4** | Attested | enforce | AA-3 + adversarial benchmark + external head witness | "integrity does not depend on the operator, and residual risk is measured" |
| **AA-5** | Certified | enforce | AA-4 + audited TCB + safety case | "an auditor/regulator can trace each safety claim to evidence" |

---

## AA-0 — None
Raw agent actions. No receipts, no chain. Nothing to verify. The status quo for
most agents today.

## AA-1 — Logged
Actions are recorded as `evidence.v1` records (observe mode; nothing is blocked).
- **Requires:** an emitter producing schema-valid records.
- **A third party can check:** the records validate against the schema. That is
  *all* — unsigned, unchained logs are corruption-detection at best, not
  tamper-evidence. Do not represent AA-1 logs as proof.

## AA-2 — Accounted
Every action produces a provenance-typed **Assurance Receipt** (`fact` /
`attested` / `claimed`) with a policy decision and capability check, appended to a
hash-chained log.
- **Requires:** the kernel `K(s,a)` in the path; records hash-chained per §5.
- **A third party can check:** the chain is internally consistent and each action
  was evaluated. **Caveat:** without a head anchor, tail truncation is still
  undetectable, and without enforcement the decision was advisory. AA-2 is "we
  recorded what we would do", not "we stopped it".

## AA-3 — Enforced
The kernel runs in **enforce / fail-closed** mode; the log is **signed and
head-anchored** (Theorem 3); **complete mediation** is established by a deployment
boundary (sandbox / egress control), not merely asserted.
- **Requires:** Theorems 1, 2, 4 under a *discharged* Assumption M (§10); signing
  key; a witnessed head; an empty/truncated log fails verification.
- **A third party with the public key and the witnessed head can check:** the log
  is intact and complete (no tamper, truncation, or wipe), and that policy-denied
  / review-gated actions carry no execution. This is the first level whose claims
  survive an adversarial reading.

## AA-4 — Attested
AA-3 plus: integrity no longer rests on the operator, and residual risk is
quantified.
- **Requires:** an **external / third-party head witness** (transparency-log-style
  anchor) so a compromised signing host cannot silently rewrite history;
  `agent-crash-lab` adversarial suites run with **published results and confidence
  bounds**; the mediation boundary **validated** by bypass tests, not just
  configured.
- **A third party can check:** the published benchmark scorecard and bounds, and
  re-verify integrity against the *external* witness without trusting the operator.

## AA-5 — Certified
AA-4 plus the assurance an auditor, regulator, or class society requires.
- **Requires:** independent audit of the TCB; a certified monitor implementation;
  managed key custody (HSM); formal review of the policy and capability model; and
  a maintained **safety case** mapping each claim → evidence (receipts, decisions,
  monitor outputs, chain integrity, benchmark results), with retention and
  revocation handled.
- **A third party can check:** the end-to-end safety argument, with every leaf
  backed by verifiable evidence — the level intended for regulated/high-impact
  autonomy.

---

### Using the levels
State a deployment's level as a claim about *verifiability*, e.g. "this workflow
operates at **AA-3**: enforced, signed, head-anchored, mediation established." A
claim above AA-2 that cannot point to enforcement + a discharged mediation
assumption + an anchored log is not that level, regardless of intent.
