# Governance

`agent-assurance-core` is the reference implementation and home of the `evidence.v1`
standard for agent action assurance. The goal of this governance is to make adopters
confident that the standard is **stable and neutral** — safe to build on without fear
of churn or a single-vendor rug-pull.

## Principles

1. **Stability over features.** `evidence.v1` (the record shape, decision labels, and
   audit-chain algorithm in [`SPEC.md`](SPEC.md)) is a wire contract. It is **frozen**
   except for additive, backward-compatible clarifications. Breaking changes ship as a
   new version (`evidence.v2`) so existing logs and implementations never silently break.
2. **Small and certifiable.** The core stays minimal, deterministic, and I/O-free (see
   [`CONTRIBUTING.md`](CONTRIBUTING.md)). Growth happens in distributions, not the kernel.
3. **One spec, many implementations.** This Rust crate is the reference, but the spec
   and [`conformance/`](conformance/) vectors are language-neutral on purpose. Other
   implementations are encouraged; conformance is defined by passing the vectors.

## Roles

- **Maintainers** review and merge changes, cut releases, and steward the spec. The
  current maintainers are listed in `MAINTAINERS` (or the repo's CODEOWNERS).
- **Contributors** propose changes via pull request (see CONTRIBUTING).
- As adoption grows, the intent is to move stewardship toward a **neutral body**
  (an open working group or foundation) rather than a single company.

## How decisions are made

- **Non-normative changes** (refactors, performance, tests, docs, bug fixes that don't
  alter emitted bytes or verification): lazy consensus — merge after at least one
  maintainer approval and green CI.
- **Normative changes** (anything touching `evidence.v1`: record fields, decision
  labels, hashing/signing, the schema): require
  1. a written proposal (issue or RFC) describing motivation and compatibility impact;
  2. a review window of at least one week for adopters to weigh in;
  3. updated `SPEC.md` **and** `conformance/` vectors in the change;
  4. approval from a majority of maintainers; and
  5. for **breaking** changes, a version bump to `evidence.v2` — never an in-place edit
     to a published version.

## Compatibility commitment

A record that validated against a published `evidence.vN` schema MUST continue to
validate against it forever. Verifiers MUST be able to read any `evidence.vN` log they
claim to support. New optional fields and new decision labels are additive and may be
introduced within a version only if older verifiers still accept the records.

## Releases & security

Releases are tagged from `main`. Security-relevant changes follow the coordinated
process in [`SECURITY.md`](SECURITY.md) and may ship out of band.

## Changing this document

Governance changes follow the normative-change process above.
