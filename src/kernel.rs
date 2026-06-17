//! The Agent Assurance Kernel: the transition `K(state, action) -> (decision,
//! state', receipt)` that ties the pieces into one decision.
//!
//! The agent is treated as an **untrusted process**; a tool call is its
//! "syscall". The kernel mediates each call and emits a provenance-typed
//! [`AssuranceReceipt`]. It enforces, by construction, the soundness invariant
//!
//! ```text
//! decision = Allow  ⇒  policy.allow(a) ∧ capability(a) ∈ caps
//!                       ∧ monitor.accept(a) ∧ budget.affords(cost(a))
//! ```
//!
//! which is the conjunction of SPEC Theorems 1 (Enforcement Soundness),
//! 2 (Capability Safety), and the Review-Gate property. Like any decision
//! engine it is deterministic and performs **no I/O** (no clock — the host
//! passes the timestamp; no disk — the host appends the evidence record).
//!
//! What the kernel does NOT establish on its own is *complete mediation* — that
//! every external action actually reaches it. In OS terms it is the syscall
//! filter, not the privilege ring; the ring (sandbox / egress control) is a
//! deployment property. See SPEC §9.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::audit::Record;
use crate::policy::{Decision, Engine, Mode};
use crate::schema::{
    decision_label as label, AssuranceReceipt, ProposedAction, ReceiptAttested, ReceiptClaimed,
    ReceiptFact, RECEIPT_SCHEMA_VERSION,
};

/// Risk class assessed for an action. Higher classes cost more budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskClass {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Budget cost. This is pure accounting — no judgment — which is exactly why
    /// a risk-budget bound is one of the few *provable* semantic safety
    /// properties: "no more than this much risk per session without re-approval".
    pub fn cost(self) -> i64 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 4,
            Self::Critical => 16,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// A depletable budget of risk. Allowing an action debits its [`RiskClass::cost`];
/// when the budget cannot cover the cost the action is held for re-approval.
#[derive(Clone, Copy, Debug)]
pub struct RiskBudget {
    pub remaining: i64,
}

impl RiskBudget {
    pub fn new(initial: i64) -> Self {
        Self { remaining: initial }
    }
    pub fn can_afford(&self, cost: i64) -> bool {
        self.remaining >= cost
    }
    pub fn debit(&mut self, cost: i64) -> bool {
        if self.can_afford(cost) {
            self.remaining -= cost;
            true
        } else {
            false
        }
    }
}

/// A set of capability names held by an agent. Capabilities bound an agent's
/// *authority* (Theorem 2); they do not, on their own, prevent misuse of granted
/// authority (the confused-deputy / prompt-injection case) — that is the
/// monitor's job, and an empirical, not provable, one.
#[derive(Clone, Debug, Default)]
pub struct CapabilitySet {
    caps: BTreeSet<String>,
}

impl CapabilitySet {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn contains(&self, cap: &str) -> bool {
        self.caps.contains(cap)
    }
    pub fn grant(&mut self, cap: impl Into<String>) {
        self.caps.insert(cap.into());
    }
    pub fn revoke(&mut self, cap: &str) {
        self.caps.remove(cap);
    }
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.caps.iter()
    }
}

impl<S: Into<String>> FromIterator<S> for CapabilitySet {
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        Self {
            caps: iter.into_iter().map(Into::into).collect(),
        }
    }
}

/// Maps an action to the capability it requires (or `None` if it needs none).
pub trait CapabilityMap: Send + Sync {
    fn required(&self, action: &ProposedAction) -> Option<String>;
}

/// Any closure is a capability map.
impl<F> CapabilityMap for F
where
    F: Fn(&ProposedAction) -> Option<String> + Send + Sync,
{
    fn required(&self, action: &ProposedAction) -> Option<String> {
        self(action)
    }
}

/// A runtime safety assessment of an action. Its output is **attested /
/// empirical** — never a proof. A sound kernel treats a rejection as a hard gate
/// but never treats acceptance as a guarantee.
#[derive(Clone, Debug)]
pub struct MonitorVerdict {
    pub accept: bool,
    pub risk: RiskClass,
    pub signals: Vec<String>,
}

impl MonitorVerdict {
    pub fn accept(risk: RiskClass) -> Self {
        Self {
            accept: true,
            risk,
            signals: Vec::new(),
        }
    }
    pub fn reject(risk: RiskClass, signal: impl Into<String>) -> Self {
        Self {
            accept: false,
            risk,
            signals: vec![signal.into()],
        }
    }
}

/// A runtime safety monitor (the "safety envelope").
pub trait Monitor: Send + Sync {
    fn assess(&self, state: &KernelState, action: &ProposedAction) -> MonitorVerdict;
}

/// A monitor that accepts everything at a fixed risk class — the "monitor off"
/// default, useful when the policy/capability layer carries the safety weight.
pub struct StaticMonitor(pub RiskClass);

impl Monitor for StaticMonitor {
    fn assess(&self, _state: &KernelState, _action: &ProposedAction) -> MonitorVerdict {
        MonitorVerdict::accept(self.0)
    }
}

/// The kernel's per-agent state — the `s_t` of the transition model. Finite and
/// fully owned by the kernel (the agent's own state is deliberately *not* here).
#[derive(Clone, Debug)]
pub struct KernelState {
    pub agent: Option<String>,
    pub capabilities: CapabilitySet,
    pub risk_budget: RiskBudget,
    /// Current chain head the next evidence record links onto.
    pub log_head: String,
    /// Number of evidence entries committed so far.
    pub seq: u64,
}

impl KernelState {
    pub fn new(
        agent: Option<String>,
        capabilities: CapabilitySet,
        risk_budget: RiskBudget,
    ) -> Self {
        Self {
            agent,
            capabilities,
            risk_budget,
            log_head: crate::audit::GENESIS.to_string(),
            seq: 0,
        }
    }
}

/// What the host should do with the action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelDecision {
    Allow,
    Deny,
    RequireHumanReview,
}

/// The result of one kernel evaluation: the decision the host must honor and the
/// receipt witnessing why.
#[derive(Clone, Debug)]
pub struct KernelOutcome {
    pub decision: KernelDecision,
    pub receipt: AssuranceReceipt,
}

impl KernelOutcome {
    /// Convenience: the hash-chainable evidence record for this outcome.
    pub fn to_evidence_record(&self) -> Record {
        self.receipt.to_evidence_record()
    }
}

/// The assurance kernel. Composes a policy [`Engine`], a [`Monitor`], and a
/// [`CapabilityMap`] into the single sound decision.
pub struct Kernel<E: Engine, M: Monitor, C: CapabilityMap> {
    pub policy: E,
    pub monitor: M,
    pub capabilities: C,
    pub mode: Mode,
    /// Digest of the policy in force, recorded as a `fact` for later audit.
    pub policy_hash: Option<String>,
    /// Identity of this attesting component (e.g. `agent-firewall`).
    pub attester: Option<String>,
}

impl<E: Engine, M: Monitor, C: CapabilityMap> Kernel<E, M, C> {
    pub fn new(policy: E, monitor: M, capabilities: C, mode: Mode) -> Self {
        Self {
            policy,
            monitor,
            capabilities,
            mode,
            policy_hash: None,
            attester: None,
        }
    }

    pub fn with_attester(mut self, who: impl Into<String>) -> Self {
        self.attester = Some(who.into());
        self
    }

    pub fn with_policy_hash(mut self, hash: impl Into<String>) -> Self {
        self.policy_hash = Some(hash.into());
        self
    }

    /// Evaluate one proposed action. Deterministic and I/O-free: the only state
    /// it mutates is the in-memory risk budget (debited when the action is truly
    /// allowed under enforcement). `ts` is supplied by the host (no clock here).
    pub fn evaluate(
        &self,
        state: &mut KernelState,
        action: &ProposedAction,
        claimed_intent: Option<String>,
        ts: impl Into<String>,
    ) -> KernelOutcome {
        let policy = self.policy.decide(action);
        let required_capability = self.capabilities.required(action);
        let capability_satisfied = match &required_capability {
            Some(c) => state.capabilities.contains(c),
            None => true,
        };
        let verdict = self.monitor.assess(state, action);
        let cost = verdict.risk.cost();
        let budget_ok = state.risk_budget.can_afford(cost);

        // The sound combination. `Allow` is reachable ONLY when policy allows,
        // the capability is held, the monitor accepts, and the budget affords —
        // the soundness invariant, by construction.
        let (enforce_decision, enforce_label, reason, policy_rule) = combine(
            &policy,
            &required_capability,
            capability_satisfied,
            &verdict,
            budget_ok,
        );

        // Observe mode forwards everything but records what enforcement WOULD do.
        let host_decision = match self.mode {
            Mode::Enforce => enforce_decision,
            Mode::Observe => KernelDecision::Allow,
        };
        let decision_label = match self.mode {
            Mode::Enforce => enforce_label,
            Mode::Observe => observe_label(enforce_label),
        };

        // Debit the budget only when the action genuinely proceeds under
        // enforcement (not in observe mode, not on deny/review).
        if self.mode == Mode::Enforce && enforce_decision == KernelDecision::Allow {
            state.risk_budget.debit(cost);
        }

        let receipt = AssuranceReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
            fact: ReceiptFact {
                action_type: action.action_type.clone(),
                tool: action.name.clone(),
                agent: state.agent.clone().or_else(|| action.agent.clone()),
                args_hash: Some(args_hash(action)),
                policy_hash: self.policy_hash.clone(),
                prev_head: state.log_head.clone(),
                head: None,
                seq: state.seq + 1,
                ts: ts.into(),
            },
            attested: ReceiptAttested {
                decision: decision_label.to_string(),
                reason,
                policy_rule,
                required_capability,
                capability_satisfied,
                monitor_accept: verdict.accept,
                risk: verdict.risk.as_str().to_string(),
                monitor_signals: verdict.signals,
                risk_budget_remaining: state.risk_budget.remaining,
                attester: self.attester.clone(),
            },
            claimed: claimed_intent.map(|intent| ReceiptClaimed {
                intent: Some(intent),
            }),
        };

        KernelOutcome {
            decision: host_decision,
            receipt,
        }
    }
}

/// sha256 over the action's arguments, serialized deterministically (serde_json
/// orders object keys), as the verifiable `args_hash` fact.
fn args_hash(action: &ProposedAction) -> String {
    let bytes = serde_json::to_vec(&action.arguments).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(&bytes);
    hex::encode(h.finalize())
}

/// The fail-closed precedence that realizes the soundness invariant. Hard
/// denials (policy block, missing capability, monitor reject) come first; then
/// review gates (policy approval, exhausted budget); only then `Allow`.
fn combine(
    policy: &Decision,
    required_capability: &Option<String>,
    capability_satisfied: bool,
    verdict: &MonitorVerdict,
    budget_ok: bool,
) -> (KernelDecision, &'static str, Option<String>, Option<String>) {
    if let Decision::Block { reason, rules } = policy {
        return (
            KernelDecision::Deny,
            label::BLOCK,
            Some(reason.clone()),
            rules.first().cloned(),
        );
    }
    if !capability_satisfied {
        let cap = required_capability.clone().unwrap_or_default();
        return (
            KernelDecision::Deny,
            label::BLOCK,
            Some(format!("missing required capability '{cap}'")),
            None,
        );
    }
    if !verdict.accept {
        let why = verdict
            .signals
            .first()
            .cloned()
            .unwrap_or_else(|| "safety monitor rejected the action".to_string());
        return (KernelDecision::Deny, label::BLOCK, Some(why), None);
    }
    if let Decision::RequireApproval { reason, rules } = policy {
        return (
            KernelDecision::RequireHumanReview,
            label::REQUIRE_APPROVAL,
            Some(reason.clone()),
            rules.first().cloned(),
        );
    }
    if !budget_ok {
        return (
            KernelDecision::RequireHumanReview,
            label::REQUIRE_APPROVAL,
            Some("risk budget exhausted; re-approval required".to_string()),
            None,
        );
    }
    (KernelDecision::Allow, label::ALLOW, None, None)
}

fn observe_label(enforce_label: &'static str) -> &'static str {
    match enforce_label {
        label::BLOCK => label::WOULD_BLOCK,
        label::REQUIRE_APPROVAL => label::WOULD_REQUIRE_APPROVAL,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Test doubles whose behavior is driven by the action arguments, so the
    // property test can sweep the full input space.
    struct ArgEngine;
    impl Engine for ArgEngine {
        fn decide(&self, a: &ProposedAction) -> Decision {
            match a.arguments["policy"].as_str() {
                Some("block") => Decision::Block {
                    reason: "blocked".into(),
                    rules: vec!["r1".into()],
                },
                Some("approval") => Decision::RequireApproval {
                    reason: "needs approval".into(),
                    rules: vec!["r2".into()],
                },
                _ => Decision::Allow,
            }
        }
    }

    struct ArgMonitor;
    impl Monitor for ArgMonitor {
        fn assess(&self, _s: &KernelState, a: &ProposedAction) -> MonitorVerdict {
            let risk = a.arguments["risk"]
                .as_str()
                .and_then(RiskClass::parse)
                .unwrap_or(RiskClass::Low);
            if a.arguments["monitor"].as_bool().unwrap_or(true) {
                MonitorVerdict::accept(risk)
            } else {
                MonitorVerdict::reject(risk, "monitor tripped")
            }
        }
    }

    fn cap_map(a: &ProposedAction) -> Option<String> {
        if a.arguments["needs_cap"].as_bool().unwrap_or(false) {
            Some("cap.x".to_string())
        } else {
            None
        }
    }

    /// Theorem-as-test: over the full cartesian product of inputs, the kernel
    /// allows an action **iff** policy allows ∧ capability held ∧ monitor accepts
    /// ∧ budget affords. This is the soundness invariant, checked biconditionally.
    #[test]
    fn allow_iff_all_conditions_hold() {
        for policy in ["allow", "block", "approval"] {
            for needs_cap in [false, true] {
                for has_cap in [false, true] {
                    for monitor in [false, true] {
                        for risk in ["low", "high"] {
                            for budget in [0i64, 100i64] {
                                let mut caps = CapabilitySet::new();
                                if has_cap {
                                    caps.grant("cap.x");
                                }
                                let mut state = KernelState::new(
                                    Some("agent".into()),
                                    caps,
                                    RiskBudget::new(budget),
                                );
                                let kernel = Kernel::new(
                                    ArgEngine,
                                    ArgMonitor,
                                    cap_map as fn(&ProposedAction) -> Option<String>,
                                    Mode::Enforce,
                                );
                                let action = ProposedAction::tool(
                                    "do",
                                    json!({
                                        "policy": policy,
                                        "needs_cap": needs_cap,
                                        "monitor": monitor,
                                        "risk": risk,
                                    }),
                                );
                                let out = kernel.evaluate(
                                    &mut state,
                                    &action,
                                    None,
                                    "2026-01-01T00:00:00Z",
                                );

                                let cap_ok = !needs_cap || has_cap;
                                let cost = RiskClass::parse(risk).unwrap().cost();
                                let budget_ok = budget >= cost;
                                let expect_allow =
                                    policy == "allow" && cap_ok && monitor && budget_ok;

                                assert_eq!(
                                    out.decision == KernelDecision::Allow,
                                    expect_allow,
                                    "policy={policy} needs_cap={needs_cap} has_cap={has_cap} \
                                     monitor={monitor} risk={risk} budget={budget}: \
                                     decision={:?}",
                                    out.decision
                                );

                                // Whenever it allows, the receipt's attested facts
                                // must corroborate every clause of the invariant.
                                if expect_allow {
                                    assert_eq!(out.receipt.attested.decision, "allow");
                                    assert!(out.receipt.attested.capability_satisfied);
                                    assert!(out.receipt.attested.monitor_accept);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn risk_budget_depletes_then_gates() {
        // Budget of 4 affords exactly one High action (cost 4); the next is held.
        let mut state =
            KernelState::new(Some("a".into()), CapabilitySet::new(), RiskBudget::new(4));
        let kernel = Kernel::new(
            ArgEngine,
            ArgMonitor,
            cap_map as fn(&ProposedAction) -> Option<String>,
            Mode::Enforce,
        );
        let high = ProposedAction::tool(
            "act",
            json!({"policy":"allow","risk":"high","monitor":true}),
        );

        let first = kernel.evaluate(&mut state, &high, None, "t1");
        assert_eq!(first.decision, KernelDecision::Allow);
        assert_eq!(state.risk_budget.remaining, 0);

        let second = kernel.evaluate(&mut state, &high, None, "t2");
        assert_eq!(second.decision, KernelDecision::RequireHumanReview);
        assert_eq!(second.receipt.attested.decision, "require_approval");
        // Budget is not debited when the action is gated.
        assert_eq!(state.risk_budget.remaining, 0);
    }

    #[test]
    fn observe_mode_forwards_but_records_would_block() {
        let mut state = KernelState::new(None, CapabilitySet::new(), RiskBudget::new(100));
        let kernel = Kernel::new(
            ArgEngine,
            StaticMonitor(RiskClass::Low),
            (|_: &ProposedAction| None) as fn(&ProposedAction) -> Option<String>,
            Mode::Observe,
        );
        let action = ProposedAction::tool("act", json!({"policy":"block"}));
        let out = kernel.evaluate(&mut state, &action, Some("ship it".into()), "t");
        // Forwarded (observe) ...
        assert_eq!(out.decision, KernelDecision::Allow);
        // ... but the receipt records what enforcement would have done, and keeps
        // the agent's claimed intent in the untrusted `claimed` group.
        assert_eq!(out.receipt.attested.decision, "would_block");
        assert_eq!(out.receipt.claimed.unwrap().intent.unwrap(), "ship it");
    }
}
