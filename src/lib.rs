//! Agent Assurance Core — an OS-style assurance kernel for untrusted AI agents.
//!
//! This crate is the small, reusable kernel shared by the agent-assurance
//! distributions. It treats the agent as an untrusted process and a tool call as
//! its "syscall": the kernel [`mediates`](kernel::Kernel::evaluate) each proposed
//! action under a policy + capability + risk-budget model, consults a pluggable
//! [`monitor`](kernel::Monitor), and emits a provenance-typed
//! [`AssuranceReceipt`](schema::AssuranceReceipt) into a hash-chained,
//! head-anchored, signed audit log.
//!
//! Modules:
//! - [`kernel`] — the transition `K(s,a)` and the soundness invariant.
//! - [`policy`] — the decision engine seam (`Allow` / `Block` / `RequireApproval`).
//! - [`schema`] — proposed actions, evidence records, and receipts (with provenance).
//! - [`audit`] — hash-chained entries, signing, and **truncation-evident** verification.
//! - [`ffi`] — the portable C ABI / WASM verification surface.
//!
//! The kernel decides and witnesses; it never acts. It is deterministic and
//! performs no I/O. Transports, adapters, and the sandbox that establishes
//! complete mediation live outside this crate. See `SPEC.md`.

pub mod audit;
pub mod ffi;
pub mod kernel;
pub mod policy;
pub mod schema;
