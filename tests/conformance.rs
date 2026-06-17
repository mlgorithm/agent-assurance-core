//! Runs the language-neutral conformance vectors (conformance/*.json) against the
//! reference implementation. Other-language implementations should run the same
//! fixtures against their own code. See SPEC.md.

use agent_assurance_core::audit::compute_hash;
use serde_json::Value;

#[test]
fn hash_chain_vectors() {
    let doc: Value =
        serde_json::from_str(include_str!("../conformance/hash-vectors.json")).unwrap();
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for v in vectors {
        let prev = v["prev"].as_str().unwrap();
        let record_bytes = v["record_bytes"].as_str().unwrap();
        let expected = v["expected_hash"].as_str().unwrap();
        assert_eq!(
            compute_hash(prev, record_bytes.as_bytes()),
            expected,
            "hash vector '{}' must match",
            v["name"]
        );
    }
}

#[test]
fn evidence_record_vectors() {
    let schema: Value =
        serde_json::from_str(include_str!("../schema/evidence-v1.schema.json")).unwrap();
    let validator = jsonschema::JSONSchema::compile(&schema).expect("schema compiles");
    let doc: Value =
        serde_json::from_str(include_str!("../conformance/evidence-records.json")).unwrap();
    for case in doc["cases"].as_array().expect("cases array") {
        let expect_valid = case["valid"].as_bool().unwrap();
        let got = validator.is_valid(&case["record"]);
        assert_eq!(
            got, expect_valid,
            "record case '{}': expected valid={expect_valid}, got {got}",
            case["name"]
        );
    }
}

#[test]
fn verify_vectors() {
    use agent_assurance_core::audit::{
        load_verifying_key_hex, verify_str_with, ExpectedHead, VerifyOptions,
    };
    let doc: Value =
        serde_json::from_str(include_str!("../conformance/verify-vectors.json")).unwrap();
    for case in doc["cases"].as_array().expect("cases array") {
        let name = case["name"].as_str().unwrap();
        let jsonl = case["jsonl"].as_str().unwrap();
        let expect_ok = case["expect_ok"].as_bool().unwrap();
        let pubkey = case
            .get("pubkey")
            .and_then(|v| v.as_str())
            .map(|h| load_verifying_key_hex(h).expect("pubkey hex"));
        let expected_head = case.get("expected_head").map(|h| ExpectedHead {
            seq: h["seq"].as_u64().unwrap(),
            hash: h["hash"].as_str().unwrap().to_string(),
        });
        let allow_empty = case
            .get("allow_empty")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let report = verify_str_with(
            jsonl,
            &VerifyOptions {
                pubkey: pubkey.as_ref(),
                expected_head,
                allow_empty,
            },
        );
        assert_eq!(
            report.ok, expect_ok,
            "verify case '{name}': expected ok={expect_ok}, got {} (err={:?})",
            report.ok, report.error
        );
    }
}
