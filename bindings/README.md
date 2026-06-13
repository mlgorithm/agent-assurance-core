# Bindings — one core, every language

The kernel exposes a small **C ABI** ([`agent_assurance.h`](agent_assurance.h)) so the
same certified core is callable from C/C++, Python, Go, embedded targets, and — compiled
to **WebAssembly** — JavaScript. The exposed surface is the **portable evidence layer**
(compute the audit link hash, verify a hash-chained signed log); it needs no randomness,
so it builds and runs on `wasm32`.

> Decisions (`Engine::decide`) are policy-specific and live in distributions; the
> universally-shared, deterministic surface is hashing + verification, which is what
> every language needs to participate in `evidence.v1`.

## Functions

| C function | Purpose |
|---|---|
| `aac_version()` | evidence schema version (static) |
| `aac_link_hash(prev_hex, bytes, len)` | `sha256(hex_decode(prev) ‖ bytes)`, lowercase hex |
| `aac_verify_log(jsonl, pubkey_hex\|NULL)` | verify chain (+ Ed25519 if a key is given) → JSON result |
| `aac_string_free(ptr)` | free a returned string |

## Build

```sh
# native dynamic + static libs (target/debug/libagent_assurance_core.{dylib,so,a})
cargo build

# WebAssembly
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown   # -> target/wasm32-unknown-unknown/debug/agent_assurance_core.wasm
```

## Use it from Python (ctypes)

[`ffi_ctypes.py`](ffi_ctypes.py) is a runnable demo + conformance check:

```sh
cargo build && python3 bindings/ffi_ctypes.py
# -> C ABI OK via ctypes: version + N hash vectors match
```

Other languages follow the same pattern: load the library, call the C functions, and
free returned strings with `aac_string_free`. Conformance is defined by the vectors in
[`../conformance/`](../conformance/) — a binding is correct iff it reproduces them.
