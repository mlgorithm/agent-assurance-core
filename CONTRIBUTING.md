# Contributing to agent-assurance-core

This repo is the **reference implementation** and home of the **`evidence.v1`
specification** ([`SPEC.md`](SPEC.md)) for agent action assurance. Contributions are
welcome — but this is a small, security-critical standard, so a few rules keep it
trustworthy.

## The one rule that matters: keep the core small and pure

The decision core MUST stay **deterministic and side-effect free** — no network, no
disk, no clock inside a decision. That property is what makes it certifiable,
replayable, and runnable identically on a server and a microcontroller. If a change
needs I/O, transport awareness, orchestration, or framework-specific glue, it belongs
in a **distribution or adapter** (the firewall, the cloud, an SDK), **not here**.

Concretely, a PR to this crate should be rejected if it:

- adds I/O, threads, time, or randomness to the decision path;
- teaches the kernel about a specific transport (MCP, HTTP, a framework). Transport
  detail goes in the evidence record's `context`, never in core fields;
- pulls in a heavy dependency. The dependency list is deliberately tiny — propose
  additions in an issue first.

## Building and testing

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test                 # lib tests + conformance vectors
cargo test --test conformance
```

A PR must pass `fmt`, `clippy -D warnings`, and all tests.

## Changing behavior = changing the standard

Most code PRs (refactors, perf, more tests, docs) are normal. But anything that changes
**what is emitted or how it's verified** — the evidence record shape, the decision
labels, the hash/signature algorithm — is a change to `evidence.v1`, the wire contract
other implementations depend on. Those PRs MUST also:

1. update [`SPEC.md`](SPEC.md) so the spec stays the source of truth;
2. update the fixtures in [`conformance/`](conformance/) (and the JSON Schema) so the
   reference and every other implementation can re-verify;
3. follow the change process in [`GOVERNANCE.md`](GOVERNANCE.md). `evidence.v1` is
   frozen except for additive, backward-compatible clarifications — breaking changes
   require a new version (`evidence.v2`), not an edit to v1.

If you add a new decision label, evidence field, or edge case, **add a conformance
vector for it** in the same PR. The conformance suite is the contract.

## Pull requests

- Keep PRs focused; describe the *why*.
- Match the surrounding style; two-space-free, `rustfmt`-clean.
- Reference an issue for anything non-trivial or normative.
- Sign your commits off with the [Developer Certificate of Origin](https://developercertificate.org/):
  `git commit -s` (adds a `Signed-off-by` line). By signing off you certify you wrote
  the change or have the right to submit it under this repo's Apache-2.0 license.

## License

By contributing you agree your contributions are licensed under **Apache-2.0**
([`LICENSE`](LICENSE)), the license for the open standard and reference implementation.

Security issues: please do **not** open a public issue — see [`SECURITY.md`](SECURITY.md).
