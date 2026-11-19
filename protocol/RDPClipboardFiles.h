#pragma once
/*
 * File clipboard helpers for MS-RDPECLIP, pure C + POSIX (no FreeRDP / ObjC):
 *
 *   Mac -> Windows: RDPFileSet is a refcounted snapshot of the top-level files the
 *     user copied. It lazily expands folders into a flat, parent-before-child
 *     FILEDESCRIPTORW list (relative '\\' paths) and serves size / range reads by
 *     listIndex for FILECONTENTS requests.
 *
 *   Windows -> Mac: rdp_clipfiles_download() materialises one top-level entry (a
 *     file, or a folder tree) of a client descriptor list into a local directory
 *     by pulling FILECONTENTS_SIZE / FILECONTENTS_RANGE chunks through a caller
 *     supplied fetch function.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include "protocol/RDPClipboardCodec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Mac -> Windows ───────────────────────────────────────────────────────── */

typedef struct RDPFileSet RDPFileSet;

/* Snapshot the top-level paths (absolute). `huge` = the peer can handle files
 * >= 2 GB; when false such files are left out of the descriptor list (Windows
 * can hang on them without huge-file support). */
RDPFileSet *rdp_fileset_create(const char *const *paths, size_t n, bool huge);
RDPFileSet *rdp_fileset_retain(RDPFileSet *s);
void        rdp_fileset_release(RDPFileSet *s);
/* Update the huge-file policy; only effective before the list is first built. */
void        rdp_fileset_set_huge(RDPFileSet *s, bool huge);
size_t      rdp_fileset_top_count(const RDPFileSet *s);

/* Expand (once) and return the descriptor list. Pointers stay valid for the life
 * of the set. Returns false on failure (e.g. nothing readable). */
bool rdp_fileset_descriptors(RDPFileSet *s, const RDPFileDesc **d, uint32_t *count);
/* Same, serialized to CLIPRDR_FILELIST (malloc'd). */
bool rdp_fileset_serialize(RDPFileSet *s, uint8_t **out, size_t *outLen);
/* Size of entry `index`. */
bool rdp_fileset_size(RDPFileSet *s, uint32_t index, uint64_t *size);
/* Read up to `len` bytes of entry `index` at `pos` into buf. Returns the number
 * of bytes read (0 at/after EOF) or -1 on error (also for directories). */
ssize_t rdp_fileset_read(RDPFileSet *s, uint32_t index, uint64_t pos, uint8_t *buf, size_t len);

/* ── Windows -> Mac ───────────────────────────────────────────────────────── */

#define RDP_CLIPFILES_CHUNK (1u << 20)   /* FILECONTENTS_RANGE request size */

/* Fetch callback. sizeOnly: ask FILECONTENTS_SIZE for listIndex (store in
 * *sizeOut). Otherwise read up to `len` bytes at `pos` into buf and report how
 * many arrived in *got. Return false on failure/timeout/cancel. */
typedef bool (*RDPFileFetchFn)(void *user, uint32_t listIndex, bool sizeOnly,
                               uint64_t pos, uint32_t len, uint8_t *buf,
                               uint32_t *got, uint64_t *sizeOut);

/* Indexes (into the descriptor list) of the top-level entries (names without a
 * path separator), in order. Returns the count; if `idx` != NULL it receives up
 * to `cap` of them. */
uint32_t rdp_clipfiles_top_entries(const RDPFileDesc *d, uint32_t n, uint32_t *idx, uint32_t cap);

/* Download top-level entry `topIndex` (an index INTO the descriptor list, as
 * returned by rdp_clipfiles_top_entries) into destRoot, recreating the folder
 * tree from the backslash relative paths. Returns the malloc'd path of the
 * created file/folder, or NULL on failure (errno-style text in *err if non-NULL,
 * static string). `cancel`, if non-NULL, aborts when it becomes non-zero. */
char *rdp_clipfiles_download(const RDPFileDesc *d, uint32_t n, uint32_t topIndex,
                             const char *destRoot, RDPFileFetchFn fetch, void *user,
                             const volatile int *cancel, const char **err);

/* Sanitize one path component for use on macOS; returns false if the component
 * must be rejected ("", ".", ".."). `dst` receives a NUL-terminated name. */
bool rdp_clipfiles_safe_component(const char *src, size_t len, char *dst, size_t cap);

#ifdef __cplusplus
}
#endif
