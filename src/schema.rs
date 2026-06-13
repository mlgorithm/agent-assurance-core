use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Canonical schema for action evidence emitted by the assurance kernel.
pub const EVIDENCE_SCHEMA_VERSION: &str = "agent-assurance.evidence.v1";

/// Canonical schema for benchmark/result envelopes that include evidence.
pub const RESULT_SCHEMA_VERSION: &str = "agent-assurance.result.v1";

/// A normalized action proposed by an agent before execution.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProposedAction {
    pub schema_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    pub action_type: String,
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
}

impl ProposedAction {
    pub fn tool(name: impl Into<String>, arguments: Value) -> ProposedAction {
        ProposedAction {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            session_id: None,
            agent: None,
            action_type: "tool_call".to_string(),
            name: name.into(),
            arguments,
            resource: None,
            transport: None,
        }
    }
}

/// A normalized result for a proposed action after execution or refusal.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ActionResult {
    pub is_error: bool,
    pub summary: String,
}

/// Decision labels used in the stable evidence JSON.
pub mod decision_label {
    pub const ALLOW: &str = "allow";
    pub const BLOCK: &str = "block";
    pub const WOULD_BLOCK: &str = "would_block";
    pub const REQUIRE_APPROVAL: &str = "require_approval";
    pub const WOULD_REQUIRE_APPROVAL: &str = "would_require_approval";
    pub const APPROVED: &str = "approved";
    pub const DENIED: &str = "denied";
    pub const TIMEOUT: &str = "timeout";
    pub const OBSERVE: &str = "observe";
}
