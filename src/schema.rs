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

    /// A proposed tool call from a known agent — the common adapter input.
    pub fn tool_call(
        agent: Option<String>,
        name: impl Into<String>,
        arguments: Value,
    ) -> ProposedAction {
        ProposedAction {
            agent,
            ..ProposedAction::tool(name, arguments)
        }
    }

    /// Set the transport label (e.g. "http", "stdio", "embedded").
    pub fn with_transport(mut self, transport: impl Into<String>) -> ProposedAction {
        self.transport = Some(transport.into());
        self
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Record, ToolInfo};
    use serde_json::json;

    /// The canonical JSON Schema both the Rust and Python emitters validate against.
    const EVIDENCE_SCHEMA: &str = include_str!("../schema/evidence-v1.schema.json");

    #[test]
    fn evidence_record_matches_published_schema() {
        let schema: serde_json::Value = serde_json::from_str(EVIDENCE_SCHEMA).unwrap();
        let validator = jsonschema::JSONSchema::compile(&schema).expect("schema compiles");

        let rec = Record {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            ts: "2026-06-13T00:00:00.000Z".to_string(),
            session_id: Some("sess-1".to_string()),
            agent: Some("alice".to_string()),
            r#type: "tool_call".to_string(),
            direction: "request".to_string(),
            tool: Some(ToolInfo {
                name: "shell".to_string(),
                arguments: json!({"cmd": "pwd"}),
            }),
            result: None,
            latency_ms: None,
            decision: decision_label::ALLOW.to_string(),
            reason: None,
            context: Some(json!({"transport": "http", "rpc_id": 1, "method": "tools/call"})),
        };
        let value = serde_json::to_value(&rec).unwrap();
        assert!(validator.is_valid(&value), "record must validate: {value}");

        // drift guard: an unknown decision label or stray field must fail
        let mut bad = value.clone();
        bad["decision"] = json!("not-a-real-decision");
        assert!(!validator.is_valid(&bad), "unknown decision must fail");
    }
}
