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
    lib.aac_verify_log.restype = ctypes.c_void_p
    lib.aac_verify_log.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.aac_verify_log_expecting.restype = ctypes.c_void_p
    lib.aac_verify_log_expecting.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_char_p
    ]
    lib.aac_string_free.argtypes = [ctypes.c_void_p]

    assert lib.aac_version() == b"agent-assurance.evidence.v1", "version mismatch"

    def _take_json(ptr):
        assert ptr, "aac_* returned NULL"
        out = ctypes.cast(ptr, ctypes.c_char_p).value.decode()
        lib.aac_string_free(ptr)
        return json.loads(out)

    def link_hash(prev, record_bytes):
        ptr = lib.aac_link_hash(prev.encode(), record_bytes, len(record_bytes))
        assert ptr, "aac_link_hash returned NULL"
        out = ctypes.cast(ptr, ctypes.c_char_p).value.decode()
        lib.aac_string_free(ptr)
        return out

    def verify(jsonl, pubkey_hex):
        pk = pubkey_hex.encode() if pubkey_hex else None
        return _take_json(lib.aac_verify_log(jsonl.encode(), pk))

    def verify_expecting(jsonl, pubkey_hex, seq, hash_hex):
        pk = pubkey_hex.encode() if pubkey_hex else None
        return _take_json(
            lib.aac_verify_log_expecting(jsonl.encode(), pk, seq, hash_hex.encode())
        )

    with open(os.path.join(ROOT, "conformance", "hash-vectors.json")) as fh:
        vectors = json.load(fh)["vectors"]

    for v in vectors:
        got = link_hash(v["prev"], v["record_bytes"].encode("utf-8"))
        assert got == v["expected_hash"], f"{v['name']}: {got} != {v['expected_hash']}"

    with open(os.path.join(ROOT, "conformance", "verify-vectors.json")) as fh:
        vv = json.load(fh)
    pubkey_hex = vv["pubkey_hex"]

    for case in vv["cases"]:
        jsonl = case["jsonl"]
        pk = pubkey_hex if case.get("pubkey", True) else None
        head = case.get("expected_head")
        res = (
            verify_expecting(jsonl, pk, head["seq"], head["hash"])
            if head
            else verify(jsonl, pk)
        )
        assert res["ok"] == case["expect"]["ok"], f"{case['name']}: {res}"
        if "entries" in case["expect"]:
            assert res["entries"] == case["expect"]["entries"], f"{case['name']}: entries"

    print(
        f"C ABI OK via ctypes: version + {len(vectors)} hash vectors "
        f"+ {len(vv['cases'])} verify vectors match"
    )


if __name__ == "__main__":
    main()
