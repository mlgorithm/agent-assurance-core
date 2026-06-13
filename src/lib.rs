//! Agent Assurance Core.
//!
//! This crate is the small, reusable kernel shared by the agent-assurance
//! distributions: policy decisions, action/evidence schemas, and verifiable
//! audit-log primitives. Product-specific transports and adapters live outside
//! this crate.

pub mod audit;
pub mod policy;
pub mod schema;
