#pragma once
/* SecurityCore: pure-C, dependency-free building blocks for the authentication
 * and session-security layer. Kept free of Foundation/FreeRDP so it can be unit
 * tested with plain clang (tests/test_security_core.c).
 *
 *   - MD4 + NT hash (NTLM password hash = MD4(UTF-16LE(password)))
 *   - SAM file text format used by WinPR's NTLM server (winpr/utils/sam.c)
 *   - login-failure / lockout bookkeeping with injectable time
 *   - size-rotated append-only audit log writer
 *
 * NEVER log or print passwords or hashes from this layer. */

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── NT hash ─────────────────────────────────────────────────────────────── */

void sc_md4(const uint8_t *data, size_t len, uint8_t out[16]);

/* NT hash of a UTF-8 password (converted to UTF-16LE first). Returns 0 on
 * success, -1 if the input is not valid UTF-8 or is absurdly long. */
int  sc_nt_hash_utf8(const char *password_utf8, uint8_t out[16]);

/* Uppercase hex of n bytes into out (needs 2n+1 bytes). */
void sc_hex_upper(const uint8_t *in, size_t n, char *out);

/* ── SAM text format ─────────────────────────────────────────────────────── *
 * One entry per line:   user:domain:lmhash:nthash:owner:
 * WinPR reads the first four fields (domain and LM hash left empty here, so the
 * line is  alias:::NTHASH:owner: ) and ignores everything after the fourth
 * colon; we keep the canonical account short name ("owner") there so every
 * alias (short name, full name, name as typed, lowercase) of one account can be
 * replaced or removed together. WinPR matches the user field case-sensitively,
 * which is why several aliases are written. Lines starting with '#' are
 * comments and are preserved. */

#define SC_SAM_NAME_MAX 128

typedef struct {
    char    user[SC_SAM_NAME_MAX];
    char    owner[SC_SAM_NAME_MAX];
    uint8_t nt[16];
} sc_sam_entry;

/* A name is usable in the SAM if it is non-empty, shorter than SC_SAM_NAME_MAX,
 * contains no ':' / CR / LF / control characters, and does not start with '#'. */
int  sc_sam_name_ok(const char *name);

/* Format one line (no trailing newline). Returns length or -1 if a name is
 * unusable or the buffer is too small. */
int  sc_sam_format_line(const char *alias, const char *owner,
                        const uint8_t nt[16], char *out, size_t outsz);

/* Parse one line. Returns 0 on success, -1 for comments/blank/malformed. A line
 * with no owner field (hand-written) gets owner = user. */
int  sc_sam_parse_line(const char *line, sc_sam_entry *out);

/* Return a malloc'd new text where every entry owned by `owner` (case-insens.)
 * or whose user field exactly equals one of `aliases` is dropped and one line
 * per distinct alias is appended. Comments are kept; malformed lines dropped
 * (a malformed line makes WinPR stop searching). NULL on invalid args/OOM. */
char *sc_sam_text_set_user(const char *text, const char *owner,
                           const char *const *aliases, size_t naliases,
                           const uint8_t nt[16]);

/* Return a malloc'd new text without any entry whose owner or user equals `name`
 * (case-insensitive). *removed (optional) receives the number of lines dropped. */
char *sc_sam_text_remove(const char *text, const char *name, int *removed);

/* Number of valid entries in text. */
size_t sc_sam_text_count(const char *text);

/* File level. Files are written atomically (temp + fsync + rename, mode 0600)
 * under an flock()ed ".lock" sibling, and the parent directory is created 0700.
 *
 * sc_sam_file_check: 0 = file usable, *count set to its entry count (may be 0);
 *   -1 = missing/unreadable (count 0); -2 = refused (not owned by this uid, a
 *   symlink, or not a regular file). Group/other permission bits are tightened to
 *   0600 when found. */
int  sc_sam_file_check(const char *path, size_t *count);

/* Returns 1 if the file changed, 0 if it already matched, -1 on error. */
int  sc_sam_file_set_user(const char *path, const char *owner,
                          const char *const *aliases, size_t naliases,
                          const uint8_t nt[16]);

/* Returns number of lines removed (>=0), or -1 on error. */
int  sc_sam_file_remove(const char *path, const char *name);

/* ── Lockout tracker ─────────────────────────────────────────────────────── *
 * Counts failures per key within a sliding window. When `threshold` failures
 * land inside `window_sec` the key is locked for base_lock_sec; with
 * double_on_repeat each further lock doubles (capped at 24 h) until the key
 * behaves for 24 h or logs in successfully. Not thread-safe: callers lock. */

typedef struct sc_lockout sc_lockout;

sc_lockout *sc_lockout_new(int threshold, int window_sec, int base_lock_sec,
                           int double_on_repeat);
void        sc_lockout_free(sc_lockout *t);

/* Seconds of lock remaining for key at `now` (0 = not locked). */
int         sc_lockout_remaining(sc_lockout *t, const char *key, time_t now);

/* Record a failure. Returns the lock duration in seconds if this failure
 * triggered a lock, else 0. Failures while already locked are ignored. */
int         sc_lockout_fail(sc_lockout *t, const char *key, time_t now);

/* Forget the key's failures and repeat-lock history (successful logon). */
void        sc_lockout_reset(sc_lockout *t, const char *key);

/* Failures currently inside the window (for logging/tests). */
int         sc_lockout_count(sc_lockout *t, const char *key, time_t now);

/* ── Audit log ───────────────────────────────────────────────────────────── */

/* Append one line (a '\n' is added) to path, mode 0600. If the file is already
 * >= max_bytes it is first renamed to path.1 (replacing any previous .1).
 * Returns 0 or -1. */
int  sc_audit_append(const char *path, const char *line, long max_bytes);

#ifdef __cplusplus
}
#endif
