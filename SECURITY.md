# Security policy

`agent-assurance-core` is a **security and evidence primitive**: other systems rely on
it to bound what an agent may do and to produce tamper-evident proof of what happened.
A bug here can be a serious vulnerability, so please treat it accordingly.

## Reporting a vulnerability

**Do not open a public issue or PR for a security problem.**

Report privately via **GitHub → Security → Report a vulnerability** (a private security
advisory on this repository), or email **security@mlgorithm.dev** *(placeholder — set
your real security contact before publishing)*.

Please include: affected version/commit, a description, and ideally a minimal
reproduction or a failing conformance-style vector. We aim to acknowledge within
**3 business days** and to agree on a disclosure timeline (target: a fix or mitigation
within **90 days**, sooner for actively exploitable issues). We'll credit reporters who
want it.

## What is in scope (high severity by default)

Anything that breaks the kernel's two guarantees — *a decision is honored* and *the
evidence is trustworthy*:

- A **tampered or forged record that still verifies** — a broken hash chain, a
  signature-verification bypass, accepting a wrong key, or a `seq`/`prev` gap that a
  verifier fails to catch.
- A way to make a **blocked action appear allowed** in the evidence, or to drop/alter
  an entry without detection.
- **Non-determinism or hidden state** in the decision path that lets the same input
  yield different decisions (it must not).
- A **fail-open** path: any condition under which the documented fail-closed behavior
  (a host can't decide or can't record) silently lets an action through *at the kernel
  contract level*.
- Cryptographic misuse: signature malleability, weak/again-usable nonces, incorrect
  Ed25519/SHA-256 usage, timing side channels in verification.

## What is out of scope

- **Policy authoring mistakes** by users of the engine (an overly permissive Cedar/
  built-in policy is a user error, not a kernel vuln).
- Vulnerabilities in **distributions** (the firewall proxy, the cloud control plane,
  adapters) — report those to their respective repositories.
- A bypass that only works because the kernel was deployed **out of the action path**
  (e.g. used as a cooperative embedded library a malicious agent can route around). The
  kernel is only a boundary when it is the only path to the action; see `SPEC.md`.

## Supported versions

Until a 1.0 release, only the latest `main` is supported with security fixes. The
`evidence.v1` wire format is covered by the compatibility commitment in
[`GOVERNANCE.md`](GOVERNANCE.md).
