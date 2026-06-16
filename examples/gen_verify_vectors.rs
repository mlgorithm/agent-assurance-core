//! Regenerate `conformance/verify-vectors.json` deterministically.
//!
//!   cargo run --example gen_verify_vectors
//!
//! Uses a FIXED, test-only signing key so the signed bytes are reproducible
//! (Ed25519 / RFC 8032 signatures are deterministic). This key is for fixtures
//! only — never use it for anything real. The logs are produced by the real
//! `AuditLog` writer, so the bytes match the reference emitter exactly.

use agent_assurance_core::audit::{AuditLog, Entry, Record, ToolInfo};
use ed25519_dalek::SigningKey;
use serde_json::json;

fn record(ts: &str, decision: &str, tool: Option<ToolInfo>, reason: Option<&str>) -> Record {
    Record {
        schema_version: Record::schema_version(),
        ts: ts.into(),
        session_id: None,
        agent: Some("alice".into()),
        r#type: "tool_call".into(),
        direction: "request".into(),
        tool,
        result: None,
        latency_ms: None,
        decision: decision.into(),
        reason: reason.map(Into::into),
        context: None,
    }
}

fn main() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey_hex = hex::encode(key.verifying_key().to_bytes());

    let dir = std::env::temp_dir().join("aac_gen_verify_vectors");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit.jsonl");
    let p = path.to_str().unwrap();

    let log = AuditLog::open_signed(p, Some(key.clone())).unwrap();
    log.append(record("2026-01-01T00:00:00.000Z", "allow", None, None))
        .unwrap();
    log.append(record(
        "2026-01-01T00:00:01.000Z",
        "require_approval",
        None,
        Some("needs sign-off"),
    ))
    .unwrap();
    log.append(record(
        "2026-01-01T00:00:02.000Z",
        "block",
        Some(ToolInfo {
            name: "wire_transfer".into(),
            arguments: json!({ "amount": 1_000_000 }),
        }),
        Some("over limit"),
    ))
    .unwrap();
    drop(log);

    let text = std::fs::read_to_string(p).unwrap();
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    assert_eq!(lines.len(), 3, "expected a 3-entry log");

    let e3: Entry = serde_json::from_str(&lines[2]).unwrap();
    let head_seq = e3.seq;
    let head_hash = e3.hash;

    let join = |ls: &[&str]| {
        let mut s = ls.join("\n");
        s.push('\n');
        s
    };
    let valid = join(&[&lines[0], &lines[1], &lines[2]]);

    // Tamper: flip the decision in entry 1 — changes its record bytes, so its
    // stored hash no longer matches.
    let tampered = valid.replacen("\"allow\"", "\"block\"", 1);

    // Forge: replace entry 1's signature with a wrong but well-formed one (the
    // hash field is untouched, so only the signature check can catch it).
    let mut e1: Entry = serde_json::from_str(&lines[0]).unwrap();
    let mut sig = e1.sig.clone().unwrap();
    let first = sig.remove(0);
    sig.insert(0, if first == '0' { '1' } else { '0' });
    e1.sig = Some(sig);
    let forged_line = serde_json::to_string(&e1).unwrap();
    let forged = join(&[&forged_line, &lines[1], &lines[2]]);

    // Reorder: swap entries 2 and 3 — seq/prev no longer line up.
    let reordered = join(&[&lines[0], &lines[2], &lines[1]]);

    // Truncate: drop the last entry.
    let truncated = join(&[&lines[0], &lines[1]]);

    let head = json!({ "seq": head_seq, "hash": head_hash });
    let cases = json!([
        { "name": "valid signed log verifies",
          "pubkey": true, "jsonl": valid.clone(),
          "expect": { "ok": true, "entries": 3 } },
        { "name": "chain-only verify (no pubkey) accepts the same log",
          "pubkey": false, "jsonl": valid.clone(),
          "expect": { "ok": true, "entries": 3 } },
        { "name": "tampered record is rejected",
          "pubkey": true, "jsonl": tampered,
          "expect": { "ok": false } },
        { "name": "forged signature is rejected",
          "pubkey": true, "jsonl": forged,
          "expect": { "ok": false } },
        { "name": "reordered entries are rejected",
          "pubkey": true, "jsonl": reordered,
          "expect": { "ok": false } },
        { "name": "truncated tail passes WITHOUT a head (the documented gap)",
          "pubkey": true, "jsonl": truncated.clone(),
          "expect": { "ok": true, "entries": 2 } },
        { "name": "truncated tail is REJECTED against the anchored head",
          "pubkey": true, "jsonl": truncated.clone(), "expected_head": head.clone(),
          "expect": { "ok": false } },
        { "name": "empty log is REJECTED against the anchored head",
          "pubkey": true, "jsonl": "", "expected_head": head.clone(),
          "expect": { "ok": false } },
        { "name": "valid log matches its anchored head",
          "pubkey": true, "jsonl": valid.clone(), "expected_head": head.clone(),
          "expect": { "ok": true, "entries": 3 } }
    ]);

    let doc = json!({
        "description":
            "Verifier conformance: whole JSONL logs with expected verify() outcomes, signed with \
             the FIXED test key below (Ed25519/RFC 8032 is deterministic). See SPEC.md sections 5 \
             and 6. Regenerate with `cargo run --example gen_verify_vectors`.",
        "pubkey_hex": pubkey_hex,
        "signing_key_hex": hex::encode(key.to_bytes()),
        "head": head,
        "cases": cases,
    });

    let out = concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/verify-vectors.json");
    std::fs::write(out, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!("wrote {out} ({} cases)", doc["cases"].as_array().unwrap().len());
}
