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
    compute_hash, load_verifying_key_hex, verify_str_with, ExpectedHead, VerifyOptions,
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

/// Verify a hash-chained log from its JSONL text (chain + optional signatures,
/// **no** head anchor — so an empty log is reported `ok:false`, but tail
/// truncation is not caught; use [`aac_verify_log_anchored`] for that).
/// `pubkey_hex` may be null to check the chain only. Returns a JSON string —
/// `{"ok":bool,"entries":<n>,"head":<hex>,"error":<string|null>}` — to free with
/// [`aac_string_free`]. Returns null if `jsonl` is null/not UTF-8.
///
/// # Safety
/// `jsonl` and (if non-null) `pubkey_hex` must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn aac_verify_log(
    jsonl: *const c_char,
    pubkey_hex: *const c_char,
) -> *mut c_char {
    verify_ffi(jsonl, pubkey_hex, 0, ptr::null())
}

/// As [`aac_verify_log`], but **head-anchored**: the log MUST end at exactly
/// `(expected_seq, expected_head_hex)`. Pass a non-null `expected_head_hex` to
/// enable the anchor (`expected_seq` is then the entry count required); pass
/// null to behave exactly like [`aac_verify_log`]. Anchoring is what makes tail
/// truncation, rollback, and wipe detectable from any language (SPEC §5).
///
/// # Safety
/// `jsonl` and any non-null pointer argument must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn aac_verify_log_anchored(
    jsonl: *const c_char,
    pubkey_hex: *const c_char,
    expected_seq: u64,
    expected_head_hex: *const c_char,
) -> *mut c_char {
    verify_ffi(jsonl, pubkey_hex, expected_seq, expected_head_hex)
}

unsafe fn verify_ffi(
    jsonl: *const c_char,
    pubkey_hex: *const c_char,
    expected_seq: u64,
    expected_head_hex: *const c_char,
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
            None => {
                return into_c_string(
                    r#"{"ok":false,"entries":0,"head":null,"error":"invalid pubkey"}"#,
                )
            }
        }
    };
    let expected_head = if expected_head_hex.is_null() {
        None
    } else {
        match CStr::from_ptr(expected_head_hex).to_str() {
            Ok(h) => Some(ExpectedHead {
                seq: expected_seq,
                hash: h.trim().to_string(),
            }),
            Err(_) => return ptr::null_mut(),
        }
    };
    let report = verify_str_with(
        text,
        &VerifyOptions {
            pubkey: pubkey.as_ref(),
            expected_head,
            allow_empty: false,
        },
    );
    let json = serde_json::json!({
        "ok": report.ok,
        "entries": report.entries,
        "head": report.head,
        "error": report.error,
    });
    into_c_string(json.to_string())
}

fn into_c_string(s: impl Into<Vec<u8>>) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}
