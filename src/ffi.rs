//! C ABI for the portable evidence surface: compute the audit link hash and
//! verify a hash-chained, optionally-signed log. This is how non-Rust callers
//! (Python via ctypes, C/C++, embedded, and — compiled to wasm32 — JavaScript)
//! participate in the `evidence.v1` standard. Verification needs no randomness,
//! so this surface builds and runs on WASM.
//!
//! Memory rule: any non-null `*mut c_char` returned here MUST be released with
//! [`aac_string_free`]. Inputs are borrowed and never freed by the callee.

use std::ffi::{c_char, CStr, CString};
use std::ptr;
use std::slice;

use crate::audit::{
    compute_hash, load_verifying_key_hex, verify_str, verify_str_with_head, Head, VerifyReport,
};

const VERSION: &[u8] = b"agent-assurance.evidence.v1\0";

/// The evidence schema version this library implements. Static; do NOT free.
#[no_mangle]
pub extern "C" fn aac_version() -> *const c_char {
    VERSION.as_ptr() as *const c_char
}

/// Free a string previously returned by this library.
///
/// # Safety
/// `s` must be a pointer returned by an `aac_*` function, or null.
#[no_mangle]
pub unsafe extern "C" fn aac_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Compute the audit link hash `sha256(hex_decode(prev) || record_bytes)` and
/// return it as a lowercase-hex, NUL-terminated string (free with
/// [`aac_string_free`]). Returns null if `prev_hex` is null/not UTF-8.
///
/// # Safety
/// `prev_hex` must be a valid NUL-terminated C string; `record_bytes` must point
/// to `record_len` readable bytes (or be null when `record_len` is 0).
#[no_mangle]
pub unsafe extern "C" fn aac_link_hash(
    prev_hex: *const c_char,
    record_bytes: *const u8,
    record_len: usize,
) -> *mut c_char {
    if prev_hex.is_null() || (record_bytes.is_null() && record_len != 0) {
        return ptr::null_mut();
    }
    let prev = match CStr::from_ptr(prev_hex).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let bytes: &[u8] = if record_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(record_bytes, record_len)
    };
    into_c_string(compute_hash(prev, bytes))
}

/// Verify a hash-chained log from its JSONL text. `pubkey_hex` may be null to
/// check the chain only (no signatures). Returns a JSON result string —
/// `{"ok":bool,"entries":<n>,"error":<string|null>}` — to free with
/// [`aac_string_free`]. Returns null if `jsonl` is null/not UTF-8.
///
/// # Safety
/// `jsonl` and (if non-null) `pubkey_hex` must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn aac_verify_log(
    jsonl: *const c_char,
    pubkey_hex: *const c_char,
) -> *mut c_char {
    if jsonl.is_null() {
        return ptr::null_mut();
    }
    let text = match CStr::from_ptr(jsonl).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let pubkey = if pubkey_hex.is_null() {
        None
    } else {
        match CStr::from_ptr(pubkey_hex)
            .to_str()
            .ok()
            .and_then(|h| load_verifying_key_hex(h).ok())
        {
            Some(k) => Some(k),
            None => return into_c_string(r#"{"ok":false,"entries":0,"error":"invalid pubkey"}"#),
        }
    };
    into_c_string(report_json(&verify_str(text, pubkey.as_ref())))
}

/// Like [`aac_verify_log`], but also assert the log reaches an out-of-band head
/// `(expected_seq, expected_hash_hex)` — how a witness detects truncation. Pass
/// `expected_hash_hex` = null to skip the head check (identical to
/// [`aac_verify_log`]). Same JSON result shape (including `head_seq`/`head_hash`).
///
/// # Safety
/// `jsonl`, and any non-null `pubkey_hex` / `expected_hash_hex`, must be valid
/// NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn aac_verify_log_expecting(
    jsonl: *const c_char,
    pubkey_hex: *const c_char,
    expected_seq: u64,
    expected_hash_hex: *const c_char,
) -> *mut c_char {
    if jsonl.is_null() {
        return ptr::null_mut();
    }
    let text = match CStr::from_ptr(jsonl).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let pubkey = if pubkey_hex.is_null() {
        None
    } else {
        match CStr::from_ptr(pubkey_hex)
            .to_str()
            .ok()
            .and_then(|h| load_verifying_key_hex(h).ok())
        {
            Some(k) => Some(k),
            None => return into_c_string(r#"{"ok":false,"entries":0,"error":"invalid pubkey","head_seq":null,"head_hash":null}"#),
        }
    };
    let expected = if expected_hash_hex.is_null() {
        None
    } else {
        match CStr::from_ptr(expected_hash_hex).to_str() {
            Ok(h) => Some(Head {
                seq: expected_seq,
                hash: h.to_string(),
            }),
            Err(_) => return ptr::null_mut(),
        }
    };
    let report = verify_str_with_head(text, pubkey.as_ref(), expected.as_ref());
    into_c_string(report_json(&report))
}

fn report_json(report: &VerifyReport) -> String {
    serde_json::json!({
        "ok": report.ok,
        "entries": report.entries,
        "error": report.error,
        "head_seq": report.head.as_ref().map(|h| h.seq),
        "head_hash": report.head.as_ref().map(|h| h.hash.clone()),
    })
    .to_string()
}

fn into_c_string(s: impl Into<Vec<u8>>) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}
