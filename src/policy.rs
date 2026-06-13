use anyhow::{bail, Result};

use crate::schema::ProposedAction;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Record what would be blocked, but forward everything.
    Observe,
    /// Actually block or gate policy violations.
    Enforce,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Mode> {
        match s.to_ascii_lowercase().as_str() {
            "observe" => Ok(Mode::Observe),
            "enforce" => Ok(Mode::Enforce),
            other => bail!("invalid mode '{other}' (expected observe|enforce)"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailMode {
    Closed,
    Open,
}

impl FailMode {
    pub fn parse(s: &str) -> Result<FailMode> {
        match s.to_ascii_lowercase().as_str() {
            "closed" => Ok(FailMode::Closed),
            "open" => Ok(FailMode::Open),
            other => bail!("invalid fail_mode '{other}' (expected closed|open)"),
        }
    }
}

/// A policy decision for one proposed agent action.
#[derive(Debug)]
pub enum Decision {
    Allow,
    Block {
        reason: String,
        rules: Vec<String>,
    },
    /// Hold the action for human approval before forwarding.
    RequireApproval {
        reason: String,
        rules: Vec<String>,
    },
}

/// A pluggable decision engine. Distributions call this before executing a
/// proposed action; the implementation can be a local matcher, Cedar, a safety
/// envelope, or another deterministic policy backend.
pub trait Engine: Send + Sync {
    /// Decide on one normalized proposed action. Every adapter (MCP, HTTP, stdio,
    /// embedded actuator) builds a `ProposedAction`, so the decision core sees one shape.
    fn decide(&self, action: &ProposedAction) -> Decision;
}
