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

/// Canonical schema for an Assurance Receipt — the kernel's per-action record.
pub const RECEIPT_SCHEMA_VERSION: &str = "agent-assurance.receipt.v1";

/// **Provenance** — how much trust a receipt field warrants. The central honesty
/// of the receipt: not all evidence is equal. A verifier must know which fields
/// it can check itself, which require trusting a component, and which are mere
/// claims by the (untrusted) agent. See SPEC §4a.
pub mod provenance {
    /// Independently checkable by anyone, trusting no producer: content hashes,
    /// the tool actually invoked, the policy digest, the chain head/seq.
    pub const FACT: &str = "fact";
    /// A verdict from a named kernel component — trustworthy *iff* you trust
    /// that component and its signing key: the policy decision, the capability
    /// check, the monitor's assessment, the remaining risk budget.
    pub const ATTESTED: &str = "attested";
    /// Self-reported by the agent (e.g. declared `intent`). Recorded for
    /// context; it is the one thing the trust model says NOT to trust.
    pub const CLAIMED: &str = "claimed";
}

/// Independently verifiable facts about an action (provenance: `fact`).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ReceiptFact {
    pub action_type: String,
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// sha256 of the canonical action arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args_hash: Option<String>,
    /// Digest of the policy in force when the decision was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// The chain head this action's evidence links onto.
    pub prev_head: String,
    /// The new chain head, once the evidence entry has been sealed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    pub seq: u64,
    pub ts: String,
}

/// Attested verdicts from kernel components (provenance: `attested`).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ReceiptAttested {
    /// The evidence decision label (see [`decision_label`]).
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_capability: Option<String>,
    pub capability_satisfied: bool,
    pub monitor_accept: bool,
    /// Risk class label assessed by the monitor (`low|medium|high|critical`).
    pub risk: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub monitor_signals: Vec<String>,
    pub risk_budget_remaining: i64,
    /// Identity of the attesting component/distribution (e.g. `agent-firewall`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester: Option<String>,
}

/// Agent self-reported context (provenance: `claimed`). **Untrusted.**
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ReceiptClaimed {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
}

/// One Assurance Receipt: the kernel's verifiable account of a single action,
/// grouped strictly by [`provenance`]. Embedded into the hash-chained evidence
/// log (in the record `context`) so it inherits Theorem-3 tamper-evidence.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AssuranceReceipt {
    pub schema_version: String,
    pub fact: ReceiptFact,
    pub attested: ReceiptAttested,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed: Option<ReceiptClaimed>,
}

impl AssuranceReceipt {
    /// Render this receipt as a hash-chainable evidence record. The full receipt
    /// is carried in the record `context`, so the provenance-typed account rides
    /// inside the head-anchored, signed chain.
    pub fn to_evidence_record(&self) -> crate::audit::Record {
        crate::audit::Record {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            ts: self.fact.ts.clone(),
            session_id: None,
            agent: self.fact.agent.clone(),
            r#type: self.fact.action_type.clone(),
            direction: "request".to_string(),
            tool: Some(crate::audit::ToolInfo {
                name: self.fact.tool.clone(),
                arguments: Value::Null,
            }),
            result: None,
            latency_ms: None,
            decision: self.attested.decision.clone(),
            reason: self.attested.reason.clone(),
            context: serde_json::to_value(self).ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Record, ToolInfo};
    use serde_json::json;

    /// The canonical JSON Schema both the Rust and Python emitters validate against.
    const EVIDENCE_SCHEMA: &str = include_str!("../schema/evidence-v1.schema.json");
    const RECEIPT_SCHEMA: &str = include_str!("../schema/agent-assurance.receipt.v1.json");

    struct AllowEngine;
    impl crate::policy::Engine for AllowEngine {
        fn decide(&self, _: &ProposedAction) -> crate::policy::Decision {
            crate::policy::Decision::Allow
        }
    }

    #[test]
    fn kernel_receipt_matches_published_schema() {
        use crate::kernel::{
            CapabilitySet, Kernel, KernelState, RiskBudget, RiskClass, StaticMonitor,
        };
        use crate::policy::Mode;

        let schema: serde_json::Value = serde_json::from_str(RECEIPT_SCHEMA).unwrap();
        let validator = jsonschema::JSONSchema::compile(&schema).expect("receipt schema compiles");

        let mut caps = CapabilitySet::new();
        caps.grant("repo.write");
        let mut state = KernelState::new(Some("alice".into()), caps, RiskBudget::new(10));
        let kernel = Kernel::new(
            AllowEngine,
            StaticMonitor(RiskClass::Medium),
            (|_: &ProposedAction| Some("repo.write".to_string()))
                as fn(&ProposedAction) -> Option<String>,
            Mode::Enforce,
        )
        .with_attester("agent-firewall")
        .with_policy_hash("sha256:deadbeef");

        let action = ProposedAction::tool_call(
            Some("alice".into()),
            "github.create_pr",
            json!({"title": "x"}),
        );
        let out = kernel.evaluate(
            &mut state,
            &action,
            Some("submit a patch".into()),
            "2026-01-01T00:00:00.000Z",
        );

        let value = serde_json::to_value(&out.receipt).unwrap();
        assert!(validator.is_valid(&value), "receipt must validate: {value}");

        // The receipt is also embeddable as a hash-chainable evidence record that
        // itself validates against evidence.v1.
        let ev_schema: serde_json::Value = serde_json::from_str(EVIDENCE_SCHEMA).unwrap();
        let ev_validator = jsonschema::JSONSchema::compile(&ev_schema).unwrap();
        let ev = serde_json::to_value(out.to_evidence_record()).unwrap();
        assert!(
            ev_validator.is_valid(&ev),
            "embedded evidence record must validate: {ev}"
        );

        // drift guard: an unknown decision label must fail.
        let mut bad = value.clone();
        bad["attested"]["decision"] = json!("nope");
        assert!(!validator.is_valid(&bad), "unknown decision must fail");
    }

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
