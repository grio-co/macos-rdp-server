#pragma once
/*
 * MS-RDPECLIP (cliprdr) engine for one RDP peer.
 *
 * Owns the FreeRDP cliprdr server context, the capability exchange, the format
 * list / format data / file contents state machines in BOTH directions, and the
 * threading rules around them. It knows nothing about NSPasteboard: the host
 * (input/ClipboardSync.m) plugs in through RDPClipHost and the rdp_clip_* calls.
 *
 * Threading (see xportLock in RDPPeer.h):
 *   - cliprdr callbacks and rdp_clip_pump run on the peer run-loop thread with
 *     ctx->xportLock held. They never block and never call into the host except
 *     the (non-blocking) client_clipboard notification.
 *   - Producing Mac->Windows bytes (host render, file reads) runs on a private
 *     serial queue and takes xportLock only for the final send.
 *   - Windows->Mac fetches (rdp_clip_fetch_*) are called from ANY thread that does
 *     not hold xportLock: they send the request under the lock, drop it, and wait
 *     (timeout) for the run-loop thread to deliver the response.
 *   - rdp_clip_destroy fails every waiter and waits for in-flight users, so a
 *     paste waiting during session teardown neither hangs nor crashes.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "protocol/RDPClipboardCodec.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RDPClipboard RDPClipboard;
typedef struct rdp_peer_context RDPPeerContext;

/* Content kinds the host can offer to / render for the client. */
enum {
    RDP_CLIP_KIND_TEXT   = 1u << 0,   /* CF_UNICODETEXT (CF_TEXT/OEMTEXT served on request) */
    RDP_CLIP_KIND_HTML   = 1u << 1,   /* "HTML Format" */
    RDP_CLIP_KIND_RTF    = 1u << 2,   /* "Rich Text Format" */
    RDP_CLIP_KIND_PNG    = 1u << 3,   /* "PNG" */
    RDP_CLIP_KIND_DIB    = 1u << 4,   /* CF_DIB */
    RDP_CLIP_KIND_DIBV5  = 1u << 5,   /* CF_DIBV5 */
    RDP_CLIP_KIND_FILES  = 1u << 6,   /* "FileGroupDescriptorW" (handled inside the engine) */
    RDP_CLIP_KIND_ANSI   = 1u << 7,   /* render-only: CF_TEXT / CF_OEMTEXT variant of TEXT */
};

typedef struct {
    uint32_t id;
    char     name[80];    /* UTF-8, "" for the predefined formats */
} RDPClipFormat;

typedef struct {
    void *user;
    /* WORKER thread. Return malloc'd bytes in the Windows wire format for `kind`
     * (CF_UNICODETEXT incl. terminator, CF_HTML, DIB, ...) or NULL if the data is
     * unavailable or the pasteboard changed since `token` (the value handed to
     * rdp_clip_advertise). The engine frees the buffer. */
    uint8_t *(*render)(void *user, uint32_t kind, uint64_t token, size_t *len);
    /* RUN-LOOP thread, xportLock held: must not block. The client took ownership
     * of its clipboard: `gen` identifies this client clipboard generation, fmts is
     * the full format list. If the client offered files, `files` is the parsed
     * FILEDESCRIPTORW list (else NULL/0). Copy what you need; pointers die on
     * return. */
    void (*client_clipboard)(void *user, uint64_t gen, const RDPClipFormat *fmts,
                             uint32_t nFmts, const RDPFileDesc *files, uint32_t nFiles);
} RDPClipHost;

/* ── lifecycle (RDPPeer.c) ────────────────────────────────────────────────── */
/* Creates + opens the channel (PostConnect). NULL if the channel could not be
 * opened. */
RDPClipboard *rdp_clip_create(RDPPeerContext *ctx);
/* Run-loop thread, once the client is activated: send Capabilities + Monitor
 * Ready. rdp_clip_pump resends Monitor Ready while the client stays silent. */
void          rdp_clip_start(RDPClipboard *c);
/* The WTS event handle to wait on (HANDLE), or NULL. */
void         *rdp_clip_event(RDPClipboard *c);
/* Run-loop thread, xportLock held: drain inbound PDUs, flush deferred sends. */
void          rdp_clip_pump(RDPClipboard *c);
/* Session teardown: fail all waiters, wait for in-flight users, free the channel.
 * Drops the context's reference. */
void          rdp_clip_destroy(RDPClipboard *c);

RDPClipboard *rdp_clip_retain(RDPClipboard *c);
void          rdp_clip_release(RDPClipboard *c);

/* ── host side ────────────────────────────────────────────────────────────── */
/* Install (non-NULL) or remove (NULL) the host. Removing waits until no host
 * callback is executing, so `user` may be freed afterwards. */
void rdp_clip_set_host(RDPClipboard *c, const RDPClipHost *host);

/* Mac -> Windows: announce what the pasteboard now holds. `token` is passed back
 * to render() so the host can detect a changed pasteboard. For KIND_FILES,
 * `paths` are the absolute top-level file/folder paths (snapshotted). Returns
 * false if the channel is gone. Safe to call before the handshake completes
 * (deferred). */
bool rdp_clip_advertise(RDPClipboard *c, uint32_t kinds, uint64_t token,
                        const char *const *paths, size_t nPaths);

/* Windows -> Mac: fetch one format of client clipboard generation `gen`. Blocks
 * (up to ~30 s) until the client answers. Returns malloc'd bytes or NULL (stale
 * generation, client refusal, timeout, teardown). Never call with xportLock held. */
uint8_t *rdp_clip_fetch_format(RDPClipboard *c, uint64_t gen, uint32_t formatId, size_t *len);

/* Windows -> Mac files: download top-level entry number `topOrdinal` (0-based,
 * among the entries without a path separator) of generation `gen` into destRoot,
 * chunk by chunk. Returns the malloc'd local path or NULL. Blocks for the whole
 * transfer (per-chunk timeout). Never call with xportLock held. */
char *rdp_clip_fetch_file(RDPClipboard *c, uint64_t gen, uint32_t topOrdinal,
                          const char *destRoot);

#ifdef __cplusplus
}
#endif
