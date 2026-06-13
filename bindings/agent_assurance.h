/* agent-assurance-core C ABI — portable evidence verification.
 *
 * Compute the audit link hash and verify a hash-chained, optionally-signed
 * evidence log from any language. See SPEC.md for the algorithms.
 *
 * Memory: any non-NULL `char *` returned here must be released with
 * aac_string_free(). Inputs are borrowed and never freed by the library.
 */
#ifndef AGENT_ASSURANCE_H
#define AGENT_ASSURANCE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Evidence schema version string (e.g. "agent-assurance.evidence.v1").
 * Statically allocated; do NOT free. */
const char *aac_version(void);

/* Free a string returned by an aac_* function. NULL is ignored. */
void aac_string_free(char *s);

/* Audit link hash: lowercase_hex( sha256( hex_decode(prev_hex) || record_bytes ) ).
 * Returns a NUL-terminated hex string to free with aac_string_free(),
 * or NULL on invalid input. */
char *aac_link_hash(const char *prev_hex,
                    const unsigned char *record_bytes,
                    size_t record_len);

/* Verify a hash-chained JSONL log. `pubkey_hex` may be NULL to check the chain
 * only (no signatures). Returns a JSON result string
 * {"ok":<bool>,"entries":<n>,"error":<string|null>} to free with
 * aac_string_free(), or NULL if `jsonl` is NULL / not UTF-8. */
char *aac_verify_log(const char *jsonl, const char *pubkey_hex);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AGENT_ASSURANCE_H */
