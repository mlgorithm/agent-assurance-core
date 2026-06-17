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
#include <stdint.h>

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

/* Verify a hash-chained JSONL log (chain + optional signatures, no head anchor).
 * `pubkey_hex` may be NULL to check the chain only. An empty log returns
 * ok:false. Returns a JSON result string
 * {"ok":<bool>,"entries":<n>,"head":<hex|null>,"error":<string|null>} to free
 * with aac_string_free(), or NULL if `jsonl` is NULL / not UTF-8. */
char *aac_verify_log(const char *jsonl, const char *pubkey_hex);

/* As aac_verify_log, but head-anchored: the log must END at exactly
 * (expected_seq, expected_head_hex). Pass expected_head_hex = NULL to disable
 * the anchor (identical to aac_verify_log). Anchoring is what makes tail
 * truncation, rollback, and wipe detectable. Same JSON result + free contract. */
char *aac_verify_log_anchored(const char *jsonl, const char *pubkey_hex,
                              uint64_t expected_seq, const char *expected_head_hex);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AGENT_ASSURANCE_H */
