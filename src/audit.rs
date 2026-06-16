use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

use crate::schema::EVIDENCE_SCHEMA_VERSION;

/// The genesis "previous hash" for the first entry: 32 zero bytes, hex-encoded.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Tool-call detail captured for an observed action.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ToolInfo {
    pub name: String,
    /// Full arguments, with detected secrets redacted when secret handling is on.
    pub arguments: serde_json::Value,
}

/// A short summary of an action result.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResultInfo {
    pub is_error: bool,
    pub summary: String,
}

/// One observed event. This is the payload that gets hash-chained and signed.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Record {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    pub ts: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    pub r#type: String,
    pub direction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<ToolInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ResultInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u128>,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Distribution-specific context, kept out of the core fields so the same
    /// record shape serves cloud software and embedded actuators alike. The
    /// MCP/HTTP proxy puts `transport`, `rpc_id`, `method`, `client_addr`, and
    /// `upstream` in here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

impl Record {
    pub fn schema_version() -> String {
        EVIDENCE_SCHEMA_VERSION.to_string()
    }
}

/// A hash-chained and optionally signed line in the audit log.
///
/// `hash = sha256(prev_hash || record_bytes)`; `sig` is an Ed25519 signature
/// over `hash` when signing is enabled.
#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub prev: String,
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    pub record: Box<RawValue>,
}

/// Thread-safe, append-only writer that maintains the hash chain and signs.
pub struct AuditLog {
    inner: Mutex<Inner>,
}

struct Inner {
    file: File,
    seq: u64,
    last_hash: String,
    signing_key: Option<SigningKey>,
}

impl AuditLog {
    /// Open or create an unsigned audit log.
    pub fn open(path: &str) -> Result<Self> {
        Self::open_signed(path, None)
    }

    /// Open or create an audit log, signing each entry if a key is supplied.
    pub fn open_signed(path: &str, signing_key: Option<SigningKey>) -> Result<Self> {
        let (seq, last_hash) = read_tail(path).unwrap_or((0, GENESIS.to_string()));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening audit log {path}"))?;
        Ok(Self {
            inner: Mutex::new(Inner {
                file,
                seq,
                last_hash,
                signing_key,
            }),
        })
    }

    /// Build a log over an already-open writer, starting a fresh chain.
    #[doc(hidden)]
    pub fn from_writer(file: File, signing_key: Option<SigningKey>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                file,
                seq: 0,
                last_hash: GENESIS.to_string(),
                signing_key,
            }),
        }
    }

    /// Append a record, returning the new entry's hash.
    pub fn append(&self, record: Record) -> Result<String> {
        let raw = serde_json::value::to_raw_value(&record)?;
        let record_bytes = raw.get().as_bytes();

        let mut guard = self.inner.lock().unwrap();
        let prev = guard.last_hash.clone();
        let prev_bytes = hex::decode(&prev).unwrap_or_else(|_| vec![0u8; 32]);

        let hash = compute_hash_from_prev_bytes(&prev_bytes, record_bytes);

        let sig = guard
            .signing_key
            .as_ref()
            .map(|k| hex::encode(k.sign(hash.as_bytes()).to_bytes()));

        let seq = guard.seq + 1;
        let entry = Entry {
            seq,
            prev,
            hash: hash.clone(),
            sig,
            record: raw,
        };
        let line = serde_json::to_string(&entry)?;
        guard.file.write_all(line.as_bytes())?;
        guard.file.write_all(b"\n")?;
        guard.file.flush()?;

        guard.seq = seq;
        guard.last_hash = hash.clone();
        Ok(hash)
    }

    /// The current head `{ seq, hash }` of the log, or `None` if nothing has been
    /// appended. Ship this to a witness so truncation can be detected later.
    pub fn head(&self) -> Option<Head> {
        let guard = self.inner.lock().unwrap();
        if guard.seq == 0 {
            None
        } else {
            Some(Head {
                seq: guard.seq,
                hash: guard.last_hash.clone(),
            })
        }
    }
}

/// A compact checkpoint of a log prefix: the sequence number and hash of the
/// terminal entry. Because the link hash chains, the terminal `hash` commits to
/// the entire log up to `seq`, and (in a signed log) it is itself signed — so a
/// `Head` retained by a witness in a separate trust domain is what lets a
/// verifier detect truncation later. See SPEC.md §5.1.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub seq: u64,
    pub hash: String,
}

/// Result of verifying an audit log's hash chain and optional signatures.
#[derive(Debug)]
pub struct VerifyReport {
    pub entries: u64,
    pub ok: bool,
    pub error: Option<String>,
    /// The terminal `{ seq, hash }` of an accepted log (`None` if empty or on
    /// failure). Persist it to use as the next `expected` head.
    pub head: Option<Head>,
}

/// Compute an entry hash from the previous hash hex and raw record bytes.
pub fn compute_hash(prev_hex: &str, record_bytes: &[u8]) -> String {
    let prev_bytes = hex::decode(prev_hex).unwrap_or_else(|_| vec![0u8; 32]);
    compute_hash_from_prev_bytes(&prev_bytes, record_bytes)
}

/// Verify an entry continues the chain from `prev` at `expected_seq`, that its
/// hash matches its bytes, and that its Ed25519 signature is valid.
pub fn verify_entry(
    entry: &Entry,
    prev: &str,
    expected_seq: u64,
    pubkey: &VerifyingKey,
) -> std::result::Result<(), String> {
    if entry.seq != expected_seq {
        return Err(format!("expected seq {expected_seq}, got {}", entry.seq));
    }
    if entry.prev != prev {
        return Err("prev-hash mismatch (chain broken)".to_string());
    }
    if compute_hash(&entry.prev, entry.record.get().as_bytes()) != entry.hash {
        return Err("hash mismatch (record tampered)".to_string());
    }
    match verify_sig(pubkey, entry) {
        Ok(true) => Ok(()),
        Ok(false) => Err("signature mismatch (forged or wrong key)".to_string()),
        Err(msg) => Err(msg),
    }
}

/// Recompute the chain from genesis and confirm every link, reading from a file.
pub fn verify_file(path: &str, pubkey: Option<&VerifyingKey>) -> Result<VerifyReport> {
    let text = std::fs::read_to_string(path)?;
    Ok(verify_str(&text, pubkey))
}

/// Like [`verify_file`], but also assert the log reaches an out-of-band
/// `expected` head — the way a witness detects truncation. See [`verify_str_with_head`].
pub fn verify_file_with_head(
    path: &str,
    pubkey: Option<&VerifyingKey>,
    expected: Option<&Head>,
) -> Result<VerifyReport> {
    let text = std::fs::read_to_string(path)?;
    Ok(verify_str_with_head(&text, pubkey, expected))
}

/// Verify a hash-chained log from its JSONL text. Infallible: malformed input
/// yields a report with `ok = false` and the first failing line. This is the
/// portable verification entry point the C ABI / WASM bindings call.
pub fn verify_str(jsonl: &str, pubkey: Option<&VerifyingKey>) -> VerifyReport {
    verify_str_with_head(jsonl, pubkey, None)
}

/// Verify a hash-chained log and, when `expected` is supplied, assert the log
/// reaches that head.
///
/// A hash chain proves nothing was altered, inserted, or reordered — but a
/// *prefix* of a valid chain is itself a valid chain, so trailing-entry deletion
/// (truncation) and whole-log deletion cannot be caught from the log alone.
/// Detection needs an out-of-band reference: a `Head { seq, hash }` retained by a
/// witness in a different trust domain from the writer. When `expected` is given,
/// this fails if the log does not reach an entry at `expected.seq` whose hash is
/// `expected.hash` — i.e. it is shorter than the head (truncated) or diverges from
/// it. A log *longer* than the head passes provided the entry at `expected.seq`
/// matches (the head is a high-water mark). See SPEC.md §5.1.
pub fn verify_str_with_head(
    jsonl: &str,
    pubkey: Option<&VerifyingKey>,
    expected: Option<&Head>,
) -> VerifyReport {
    let mut prev = GENESIS.to_string();
    let mut expected_seq = 1u64;
    let mut count = 0u64;
    let mut hash_at_expected: Option<String> = None;

    for (idx, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let lineno = idx + 1;

        let entry: Entry = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(e) => return fail(count, format!("line {lineno}: parse error: {e}")),
        };

        if entry.seq != expected_seq {
            return fail(
                count,
                format!("line {lineno}: expected seq {expected_seq}, got {}", entry.seq),
            );
        }
        if entry.prev != prev {
            return fail(count, format!("line {lineno}: prev-hash mismatch (chain broken)"));
        }

        let prev_bytes = hex::decode(&entry.prev).unwrap_or_else(|_| vec![0u8; 32]);
        let mut hasher = Sha256::new();
        hasher.update(&prev_bytes);
        hasher.update(entry.record.get().as_bytes());
        let computed = hex::encode(hasher.finalize());
        if computed != entry.hash {
            return fail(count, format!("line {lineno}: hash mismatch (record tampered)"));
        }

        if let Some(pk) = pubkey {
            match verify_sig(pk, &entry) {
                Ok(true) => {}
                Ok(false) => {
                    return fail(
                        count,
                        format!("line {lineno}: signature mismatch (forged or wrong key)"),
                    )
                }
                Err(msg) => return fail(count, format!("line {lineno}: {msg}")),
            }
        }

        prev = entry.hash;
        if let Some(exp) = expected {
            if entry.seq == exp.seq {
                hash_at_expected = Some(prev.clone());
            }
        }
        expected_seq += 1;
        count += 1;
    }

    // Truncation / head check against the out-of-band anchor.
    if let Some(exp) = expected {
        match &hash_at_expected {
            None => {
                let missing = exp.seq.saturating_sub(count);
                return fail(
                    count,
                    format!(
                        "log truncated: ends at seq {count}, but a signed head was anchored at \
                         seq {} ({missing} entr{} missing)",
                        exp.seq,
                        if missing == 1 { "y" } else { "ies" }
                    ),
                );
            }
            Some(h) if *h != exp.hash => {
                return fail(
                    count,
                    format!("head mismatch at seq {}: log diverges from the anchored head", exp.seq),
                );
            }
            Some(_) => {}
        }
    }

    let head = if count > 0 {
        Some(Head {
            seq: count,
            hash: prev,
        })
    } else {
        None
    };
    VerifyReport {
        entries: count,
        ok: true,
        error: None,
        head,
    }
}

/// Generate a fresh Ed25519 signing key.
pub fn generate_signing_key() -> SigningKey {
    use rand_core::OsRng;
    SigningKey::generate(&mut OsRng)
}

/// Produce a signed entry. Used by tests and sample generators.
pub fn seal(prev: &str, seq: u64, record: &serde_json::Value, key: &SigningKey) -> Entry {
    let raw = serde_json::value::to_raw_value(record).expect("serialize record");
    let hash = compute_hash(prev, raw.get().as_bytes());
    let sig = hex::encode(key.sign(hash.as_bytes()).to_bytes());
    Entry {
        seq,
        prev: prev.to_string(),
        hash,
        sig: Some(sig),
        record: raw,
    }
}

/// Load a hex-encoded 32-byte Ed25519 signing key from a file.
pub fn load_signing_key(path: &str) -> Result<SigningKey> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading signing key {path}"))?;
    let bytes = hex::decode(text.trim()).context("decoding signing key hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("signing key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Load a hex-encoded 32-byte Ed25519 public verifying key from a file.
pub fn load_verifying_key(path: &str) -> Result<VerifyingKey> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading public key {path}"))?;
    let bytes = hex::decode(text.trim()).context("decoding public key hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| anyhow!("invalid public key: {e}"))
}

/// Load a hex-encoded 32-byte Ed25519 public verifying key from a string.
pub fn load_verifying_key_hex(hexs: &str) -> std::result::Result<VerifyingKey, String> {
    let bytes = hex::decode(hexs.trim()).map_err(|_| "pubkey not hex".to_string())?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid pubkey: {e}"))
}

fn read_tail(path: &str) -> Option<(u64, String)> {
    let f = File::open(path).ok()?;
    let reader = BufReader::new(f);
    let mut last: Option<(u64, String)> = None;
    for line in reader.lines() {
        let line = line.ok()?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(e) = serde_json::from_str::<Entry>(&line) {
            last = Some((e.seq, e.hash));
        }
    }
    last
}

fn verify_sig(pk: &VerifyingKey, entry: &Entry) -> std::result::Result<bool, String> {
    let sighex = entry
        .sig
        .as_ref()
        .ok_or_else(|| "missing signature (expected a signed log)".to_string())?;
    let bytes = hex::decode(sighex).map_err(|_| "signature is not valid hex".to_string())?;
    let arr: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let sig = Signature::from_bytes(&arr);
    Ok(pk.verify_strict(entry.hash.as_bytes(), &sig).is_ok())
}

fn compute_hash_from_prev_bytes(prev_bytes: &[u8], record_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_bytes);
    hasher.update(record_bytes);
    hex::encode(hasher.finalize())
}

fn default_schema_version() -> String {
    EVIDENCE_SCHEMA_VERSION.to_string()
}

fn fail(entries: u64, msg: String) -> VerifyReport {
    VerifyReport {
        entries,
        ok: false,
        error: Some(msg),
        head: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_log_verifies_and_detects_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let key = generate_signing_key();
        let log = AuditLog::open_signed(path.to_str().unwrap(), Some(key.clone())).unwrap();

        log.append(Record {
            schema_version: Record::schema_version(),
            ts: "2026-06-13T00:00:00Z".to_string(),
            session_id: Some("sess-1".to_string()),
            agent: Some("agent-1".to_string()),
            r#type: "tool_call".to_string(),
            direction: "request".to_string(),
            tool: Some(ToolInfo {
                name: "shell".to_string(),
                arguments: serde_json::json!({"cmd": "pwd"}),
            }),
            result: None,
            latency_ms: None,
            decision: "allow".to_string(),
            reason: None,
            context: Some(serde_json::json!({"transport": "test", "method": "tools/call"})),
        })
        .unwrap();

        let report = verify_file(path.to_str().unwrap(), Some(&key.verifying_key())).unwrap();
        assert!(report.ok);
        assert_eq!(report.entries, 1);

        let mut text = std::fs::read_to_string(&path).unwrap();
        text = text.replace("\"allow\"", "\"block\"");
        std::fs::write(&path, text).unwrap();

        let report = verify_file(path.to_str().unwrap(), Some(&key.verifying_key())).unwrap();
        assert!(!report.ok);
        assert!(report
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("hash mismatch"));
    }

    #[test]
    fn truncation_is_caught_against_an_anchored_head() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let p = path.to_str().unwrap();
        let key = generate_signing_key();
        let pk = key.verifying_key();

        let log = AuditLog::open_signed(p, Some(key.clone())).unwrap();
        for i in 0..3 {
            log.append(Record {
                schema_version: Record::schema_version(),
                ts: format!("2026-06-15T00:00:0{i}Z"),
                session_id: None,
                agent: None,
                r#type: "tool_call".into(),
                direction: "request".into(),
                tool: None,
                result: None,
                latency_ms: None,
                decision: "allow".into(),
                reason: None,
                context: None,
            })
            .unwrap();
        }
        // The witness retains the head it saw.
        let anchored = log.head().expect("3 entries -> a head");
        assert_eq!(anchored.seq, 3);
        drop(log);

        // A clean log verifies, and against its own head, and reports that head.
        let clean = verify_file_with_head(p, Some(&pk), Some(&anchored)).unwrap();
        assert!(clean.ok);
        assert_eq!(clean.head.as_ref(), Some(&anchored));

        // Attacker (no key) deletes the last line.
        let text = std::fs::read_to_string(p).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.pop();
        std::fs::write(p, lines.join("\n") + "\n").unwrap();

        // Without a head, truncation still slips through (the documented gap)...
        let blind = verify_file(p, Some(&pk)).unwrap();
        assert!(blind.ok);
        assert_eq!(blind.entries, 2);

        // ...but against the anchored head it is caught.
        let caught = verify_file_with_head(p, Some(&pk), Some(&anchored)).unwrap();
        assert!(!caught.ok);
        assert!(caught.error.as_deref().unwrap_or_default().contains("truncated"));

        // A wholly deleted log is caught too.
        std::fs::write(p, "").unwrap();
        let empty = verify_file_with_head(p, Some(&pk), Some(&anchored)).unwrap();
        assert!(!empty.ok);
    }
}
