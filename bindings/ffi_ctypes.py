#!/usr/bin/env python3
"""Call the agent-assurance-core C ABI from Python via ctypes, and check it against
the language-neutral conformance vectors. This is the cross-language proof that the
same certified core runs everywhere.

Build the library first:  cargo build   (produces target/debug/libagent_assurance_core.*)
Run:                       python3 bindings/ffi_ctypes.py
"""
import ctypes
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_lib():
    pats = ["libagent_assurance_core.dylib", "libagent_assurance_core.so", "agent_assurance_core.dll"]
    for prof in ("debug", "release"):
        for pat in pats:
            hits = glob.glob(os.path.join(ROOT, "target", prof, pat))
            if hits:
                return ctypes.CDLL(hits[0])
    sys.exit("library not found — run `cargo build` first")


def main():
    lib = _load_lib()
    lib.aac_version.restype = ctypes.c_char_p
    lib.aac_link_hash.restype = ctypes.c_void_p
    lib.aac_link_hash.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.aac_string_free.argtypes = [ctypes.c_void_p]

    assert lib.aac_version() == b"agent-assurance.evidence.v1", "version mismatch"

    def link_hash(prev, record_bytes):
        ptr = lib.aac_link_hash(prev.encode(), record_bytes, len(record_bytes))
        assert ptr, "aac_link_hash returned NULL"
        out = ctypes.cast(ptr, ctypes.c_char_p).value.decode()
        lib.aac_string_free(ptr)
        return out

    with open(os.path.join(ROOT, "conformance", "hash-vectors.json")) as fh:
        vectors = json.load(fh)["vectors"]

    for v in vectors:
        got = link_hash(v["prev"], v["record_bytes"].encode("utf-8"))
        assert got == v["expected_hash"], f"{v['name']}: {got} != {v['expected_hash']}"

    # Verifier conformance — run the SAME verify-vectors the Rust suite runs,
    # including the head-anchored truncation cases, through the C ABI.
    lib.aac_verify_log.restype = ctypes.c_void_p
    lib.aac_verify_log.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.aac_verify_log_anchored.restype = ctypes.c_void_p
    lib.aac_verify_log_anchored.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_uint64,
        ctypes.c_char_p,
    ]

    def verify(jsonl, pubkey=None, anchor=None):
        pk = pubkey.encode() if pubkey else None
        if anchor is None:
            ptr = lib.aac_verify_log(jsonl.encode(), pk)
        else:
            ptr = lib.aac_verify_log_anchored(
                jsonl.encode(), pk, anchor["seq"], anchor["hash"].encode()
            )
        out = ctypes.cast(ptr, ctypes.c_char_p).value.decode()
        lib.aac_string_free(ptr)
        return json.loads(out)

    with open(os.path.join(ROOT, "conformance", "verify-vectors.json")) as fh:
        vcases = json.load(fh)["cases"]

    ran = 0
    for c in vcases:
        # The C ABI has no `allow_empty` flag (default is fail-closed), so skip
        # the one case that needs it; every other case must agree exactly.
        if c.get("allow_empty"):
            continue
        res = verify(c["jsonl"], c.get("pubkey"), c.get("expected_head"))
        assert res["ok"] == c["expect_ok"], f"{c['name']}: {res} != expect_ok={c['expect_ok']}"
        ran += 1

    print(
        f"C ABI OK via ctypes: version + {len(vectors)} hash vectors "
        f"+ {ran} verify vectors (incl. truncation) match"
    )


if __name__ == "__main__":
    main()
