#include "protocol/RDPClipboard.h"
#include "protocol/RDPClipboardFiles.h"
#include "protocol/RDPPeer.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <dispatch/dispatch.h>

#include <freerdp/server/cliprdr.h>
#include <freerdp/channels/cliprdr.h>
#include <winpr/synch.h>

#define RDP_LOG_COMPONENT "clipboard"
#include "logging/RDPLog.h"

/* Registered-format ids we hand out in the Format List. Windows treats ids in
 * 0xC000..0xFFFF as session-local names, so any stable value works. */
#define FMT_ID_HTML   0xC101u
#define FMT_ID_RTF    0xC102u
#define FMT_ID_PNG    0xC103u
#define FMT_ID_FILES  0xC104u

#define FETCH_TIMEOUT_MS      30000
#define FILE_CHUNK_TIMEOUT_MS 30000
#define STUCK_REQUEST_MS      60000
#define MAX_CLIENT_PAYLOAD    (768u * 1024u * 1024u)
#define MAX_RANGE_REQUEST     (32u * 1024u * 1024u)
#define MAX_LOCKS             16
#define ECHO_WINDOW_MS        3000

/* ── data structures ──────────────────────────────────────────────────────── */

typedef struct DataReq {
    struct DataReq *next;
    int       refs;             /* guarded by c->mu */
    uint32_t  formatId;
    uint64_t  gen;
    bool      internal;         /* FileGroupDescriptorW fetch driven by the engine */
    bool      sent, done, ok, abandoned;
    uint64_t  sentAt;
    uint8_t  *data;
    size_t    len;
} DataReq;

typedef struct FileReq {
    struct FileReq *next;
    uint32_t  streamId;
    bool      done, ok;
    uint8_t  *data;
    uint32_t  len;
} FileReq;

typedef struct {
    int          refs;          /* guarded by c->mu */
    RDPFileDesc *d;
    uint32_t     n;
} ClientFiles;

struct RDPClipboard {
    int                   refs;
    RDPPeerContext       *ctx;        /* valid only while !closed and users > 0 */
    CliprdrServerContext *cliprdr;
    pthread_mutex_t       mu;
    pthread_cond_t        cv;
    dispatch_queue_t      q;
    bool                  closed;
    volatile int          abortFlag;
    int                   users;      /* in-flight users of ctx/cliprdr */
    int                   hostUsers;  /* in-flight host callbacks */
    RDPClipHost           host;
    bool                  hostSet;

    bool      ready;                  /* client engaged the channel */
    bool      capsSeen;
    bool      wantFiles, wantLock;    /* env switches */

    /* Mac -> Windows (we own the clipboard) */
    bool       ownPending;
    uint32_t   ownKinds;
    uint64_t   ownToken;
    uint64_t   ownGen;
    uint64_t   ownAdvertisedAt;
    RDPFileSet *ownFiles;
    struct { bool used; uint32_t id; RDPFileSet *set; } locks[MAX_LOCKS];
    int        lockNext;

    /* Windows -> Mac (the client owns the clipboard) */
    uint64_t       clientGen;
    RDPClipFormat *cfmts;             /* run-loop thread only */
    uint32_t       ncfmts;
    ClientFiles   *cfiles;            /* guarded by mu */
    bool           lockSent;
    uint32_t       lockId;
    uint64_t       lockGen;
    DataReq       *reqHead, *reqTail;
    FileReq       *freqs;
    uint32_t       nextStream;
};

static const uint8_t kDummy[8] = {0};

/* ── small helpers ────────────────────────────────────────────────────────── */

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static bool use_begin(RDPClipboard *c) {
    pthread_mutex_lock(&c->mu);
    bool ok = !c->closed;
    if (ok) c->users++;
    pthread_mutex_unlock(&c->mu);
    return ok;
}
static void use_end(RDPClipboard *c) {
    pthread_mutex_lock(&c->mu);
    if (--c->users == 0) pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mu);
}

/* Host callback guard: copies the host table out so the call runs unlocked. */
static bool host_enter(RDPClipboard *c, RDPClipHost *out) {
    pthread_mutex_lock(&c->mu);
    bool ok = c->hostSet;
    if (ok) { *out = c->host; c->hostUsers++; }
    pthread_mutex_unlock(&c->mu);
    return ok;
}
static void host_leave(RDPClipboard *c) {
    pthread_mutex_lock(&c->mu);
    if (--c->hostUsers == 0) pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mu);
}

/* Remaining-time-aware wait; mu must be held. Returns false on timeout. */
static bool cv_wait_until(RDPClipboard *c, uint64_t deadline) {
    uint64_t now = now_ms();
    if (now >= deadline) return false;
    uint64_t rem = deadline - now;
    if (rem > 1000) rem = 1000;     /* slice so closed/stale are re-checked */
    struct timespec ts = { .tv_sec = (time_t)(rem / 1000), .tv_nsec = (long)(rem % 1000) * 1000000L };
    pthread_cond_timedwait_relative_np(&c->cv, &c->mu, &ts);
    return true;
}

static void req_unref_locked(DataReq *r) {
    if (--r->refs == 0) { free(r->data); free(r); }
}

static void client_files_unref_locked(ClientFiles *cf) {
    if (cf && --cf->refs == 0) { rdp_filelist_free(cf->d, cf->n); free(cf); }
}

static RDPFileSet *fileset_for_lock_locked(RDPClipboard *c, bool haveId, uint32_t id) {
    if (haveId)
        for (int i = 0; i < MAX_LOCKS; i++)
            if (c->locks[i].used && c->locks[i].id == id) return rdp_fileset_retain(c->locks[i].set);
    return rdp_fileset_retain(c->ownFiles);   /* may be NULL */
}

/* ── kinds <-> formats ────────────────────────────────────────────────────── */

typedef struct { uint32_t kind; uint32_t id; const char *name; } KindFmt;
static const KindFmt kKinds[] = {
    { RDP_CLIP_KIND_TEXT,  RDP_CF_UNICODETEXT, ""                    },
    { RDP_CLIP_KIND_HTML,  FMT_ID_HTML,        RDP_FMT_NAME_HTML     },
    { RDP_CLIP_KIND_RTF,   FMT_ID_RTF,         RDP_FMT_NAME_RTF      },
    { RDP_CLIP_KIND_PNG,   FMT_ID_PNG,         RDP_FMT_NAME_PNG      },
    { RDP_CLIP_KIND_DIB,   RDP_CF_DIB,         ""                    },
    { RDP_CLIP_KIND_DIBV5, RDP_CF_DIBV5,       ""                    },
    { RDP_CLIP_KIND_FILES, FMT_ID_FILES,       RDP_FMT_NAME_FILES    },
};
#define N_KINDS (sizeof(kKinds) / sizeof(kKinds[0]))

/* Which kind does a client-requested format id map to, given what we offered? */
static uint32_t kind_for_id(uint32_t kinds, uint32_t id) {
    if (id == RDP_CF_TEXT || id == RDP_CF_OEMTEXT)
        return (kinds & RDP_CLIP_KIND_TEXT) ? RDP_CLIP_KIND_ANSI : 0;
    for (size_t i = 0; i < N_KINDS; i++)
        if (kKinds[i].id == id) return (kinds & kKinds[i].kind) ? kKinds[i].kind : 0;
    return 0;
}

/* Send the Format List for `kinds`. Needs use + xportLock (recursive). */
static void send_format_list(RDPClipboard *c, uint32_t kinds) {
    CLIPRDR_FORMAT fmts[N_KINDS];
    UINT32 n = 0;
    bool longNames = c->cliprdr->useLongFormatNames;
    for (size_t i = 0; i < N_KINDS; i++) {
        if (!(kinds & kKinds[i].kind)) continue;
        /* Registered formats need a name; the short (32-byte) form truncates it. */
        if (kKinds[i].name[0] && !longNames) continue;
        if (kKinds[i].kind == RDP_CLIP_KIND_FILES && !c->cliprdr->streamFileClipEnabled) continue;
        /* formatName MUST be non-NULL (see FreeRDP cliprdr_packet_format_list_new). */
        fmts[n].formatId = kKinds[i].id;
        fmts[n].formatName = (char *)kKinds[i].name;
        n++;
    }
    if (n == 0) { rdp_verbose("clipboard: nothing advertisable for kinds 0x%x", kinds); return; }
    CLIPRDR_FORMAT_LIST list = {0};
    list.common.msgType  = CB_FORMAT_LIST;
    list.common.msgFlags = 0;
    list.numFormats = n;
    list.formats = fmts;
    pthread_mutex_lock(&c->ctx->xportLock);
    UINT rc = c->cliprdr->ServerFormatList(c->cliprdr, &list);
    pthread_mutex_unlock(&c->ctx->xportLock);
    rdp_verbose("clipboard: -> FormatList (%u formats, kinds=0x%x, rc=%u)", n, kinds, rc);
}

static void flush_advertise(RDPClipboard *c) {
    pthread_mutex_lock(&c->mu);
    if (c->closed || !c->ready || !c->ownPending) { pthread_mutex_unlock(&c->mu); return; }
    uint32_t kinds = c->ownKinds;
    c->ownPending = false;
    pthread_mutex_unlock(&c->mu);
    if (!use_begin(c)) return;
    send_format_list(c, kinds);
    use_end(c);
}

/* ── request queue (we ask the client for data) ───────────────────────────── */

/* Send the next unsent request if nothing is on the wire. use + xportLock. */
static void pump_requests(RDPClipboard *c) {
    for (;;) {
        DataReq *r = NULL;
        pthread_mutex_lock(&c->mu);
        uint64_t now = now_ms();
        while (c->reqHead) {
            DataReq *h = c->reqHead;
            if (h->sent) {
                if (now - h->sentAt <= STUCK_REQUEST_MS) break;       /* still waiting */
                rdp_verbose("clipboard: dropping unanswered format data request 0x%x", h->formatId);
            } else if (!h->abandoned) {
                h->sent = true; h->sentAt = now; r = h;
                break;
            }
            /* abandoned-before-send, or stuck: drop it */
            c->reqHead = h->next;
            if (!c->reqHead) c->reqTail = NULL;
            if (!h->done) { h->done = true; h->ok = false; }
            pthread_cond_broadcast(&c->cv);
            req_unref_locked(h);
        }
        pthread_mutex_unlock(&c->mu);
        if (!r) return;

        CLIPRDR_FORMAT_DATA_REQUEST dreq = {0};
        dreq.common.msgType  = CB_FORMAT_DATA_REQUEST;
        /* dataLen MUST be 4: FreeRDP allocates (dataLen + 8) and then writes the 4-byte
         * requestedFormatId after the header; 0 overruns the stream and aborts. */
        dreq.common.dataLen  = 4;
        dreq.requestedFormatId = r->formatId;
        pthread_mutex_lock(&c->ctx->xportLock);
        UINT rc = c->cliprdr->ServerFormatDataRequest(c->cliprdr, &dreq);
        pthread_mutex_unlock(&c->ctx->xportLock);
        rdp_verbose("clipboard: -> FormatDataRequest 0x%x (rc=%u)", r->formatId, rc);
        if (rc == CHANNEL_RC_OK) return;

        /* send failed: fail this request and try the next one */
        pthread_mutex_lock(&c->mu);
        if (c->reqHead == r) {
            c->reqHead = r->next;
            if (!c->reqHead) c->reqTail = NULL;
            r->done = true; r->ok = false;
            pthread_cond_broadcast(&c->cv);
            req_unref_locked(r);
        }
        pthread_mutex_unlock(&c->mu);
    }
}

static void notify_host_client(RDPClipboard *c, uint64_t gen, const RDPFileDesc *files, uint32_t nf) {
    RDPClipHost h;
    if (!host_enter(c, &h)) return;
    if (h.client_clipboard) h.client_clipboard(h.user, gen, c->cfmts, c->ncfmts, files, nf);
    host_leave(c);
}

/* The FileGroupDescriptorW answer arrived (run-loop thread, xportLock held). */
static void descriptors_arrived(RDPClipboard *c, uint64_t gen, bool ok, const uint8_t *data, size_t len) {
    pthread_mutex_lock(&c->mu);
    bool stale = (gen != c->clientGen);
    pthread_mutex_unlock(&c->mu);
    if (stale) return;
    RDPFileDesc *files = NULL;
    uint32_t nf = 0;
    if (ok && rdp_filelist_parse(data, len, &files, &nf) && nf > 0) {
        ClientFiles *cf = (ClientFiles *)calloc(1, sizeof(*cf));
        if (cf) {
            cf->refs = 1; cf->d = files; cf->n = nf;
            pthread_mutex_lock(&c->mu);
            client_files_unref_locked(c->cfiles);
            c->cfiles = cf;
            pthread_mutex_unlock(&c->mu);
            rdp_verbose("clipboard: client offers %u file entries", nf);
            notify_host_client(c, gen, files, nf);
            return;
        }
        rdp_filelist_free(files, nf);
    }
    rdp_verbose("clipboard: client file list unusable — treating the copy as non-file");
    notify_host_client(c, gen, NULL, 0);
}

/* ── cliprdr callbacks: capabilities / format lists ───────────────────────── */

static UINT cb_client_capabilities(CliprdrServerContext *cl, const CLIPRDR_CAPABILITIES *caps) {
    RDPClipboard *c = (RDPClipboard *)cl->custom;
    UINT32 flags = 0, version = 0;
    for (UINT32 i = 0; i < caps->cCapabilitiesSets; i++) {
        const CLIPRDR_CAPABILITY_SET *set = &caps->capabilitySets[i];
        if (set->capabilitySetType == CB_CAPSTYPE_GENERAL) {
            const CLIPRDR_GENERAL_CAPABILITY_SET *g = (const CLIPRDR_GENERAL_CAPABILITY_SET *)set;
            version = g->version; flags = g->generalFlags;
        }
    }
    pthread_mutex_lock(&c->mu);
    c->ready = true;
    c->capsSeen = true;
    RDPFileSet *fs = rdp_fileset_retain(c->ownFiles);
    bool huge = cl->hasHugeFileSupport;
    pthread_mutex_unlock(&c->mu);
    if (fs) { rdp_fileset_set_huge(fs, huge); rdp_fileset_release(fs); }
    /* FreeRDP has already narrowed the context's feature flags by the client's. */
    rdp_verbose("clipboard: <- ClientCapabilities (version=0x%x flags=0x%x) negotiated: "
                "longNames=%d files=%d noPaths=%d lock=%d huge=%d",
                version, flags, cl->useLongFormatNames, cl->streamFileClipEnabled,
                cl->fileClipNoFilePaths, cl->canLockClipData, cl->hasHugeFileSupport);
    return CHANNEL_RC_OK;
}

static UINT cb_client_format_list_response(CliprdrServerContext *cl,
                                           const CLIPRDR_FORMAT_LIST_RESPONSE *resp) {
    (void)cl;
    rdp_verbose("clipboard: <- FormatListResponse (%s)",
                (resp->common.msgFlags & CB_RESPONSE_OK) ? "OK" : "FAIL");
    return CHANNEL_RC_OK;
}

static bool is_echo_locked(RDPClipboard *c, const CLIPRDR_FORMAT_LIST *list) {
    if (!c->ownKinds || now_ms() - c->ownAdvertisedAt > ECHO_WINDOW_MS) return false;
    uint32_t want = 0;
    for (size_t i = 0; i < N_KINDS; i++) if (c->ownKinds & kKinds[i].kind) want++;
    if (list->numFormats != want) return false;
    for (UINT32 i = 0; i < list->numFormats; i++) {
        bool found = false;
        for (size_t k = 0; k < N_KINDS; k++)
            if ((c->ownKinds & kKinds[k].kind) && kKinds[k].id == list->formats[i].formatId) found = true;
        if (!found) return false;
    }
    return true;
}

static UINT cb_client_format_list(CliprdrServerContext *cl, const CLIPRDR_FORMAT_LIST *list) {
    RDPClipboard *c = (RDPClipboard *)cl->custom;
    rdp_verbose("clipboard: <- ClientFormatList (%u formats)", list->numFormats);
    for (UINT32 i = 0; i < list->numFormats; i++)
        rdp_verbose("clipboard:    format[%u] id=0x%08x name=%s", i, list->formats[i].formatId,
                    list->formats[i].formatName ? list->formats[i].formatName : "(none)");

    /* ACK first. */
    CLIPRDR_FORMAT_LIST_RESPONSE resp = {0};
    resp.common.msgType  = CB_FORMAT_LIST_RESPONSE;
    resp.common.msgFlags = CB_RESPONSE_OK;
    cl->ServerFormatListResponse(cl, &resp);

    pthread_mutex_lock(&c->mu);
    c->ready = true;
    if (is_echo_locked(c, list)) {
        pthread_mutex_unlock(&c->mu);
        rdp_verbose("clipboard: client format list echoes our own advertise — ignored");
        return CHANNEL_RC_OK;
    }
    uint64_t gen = ++c->clientGen;
    /* Invalidate everything tied to the previous client clipboard. */
    bool unlock = c->lockSent;
    uint32_t oldLock = c->lockId;
    c->lockSent = false;
    client_files_unref_locked(c->cfiles);
    c->cfiles = NULL;
    for (DataReq *r = c->reqHead; r; r = r->next) {
        if (r->gen == gen) continue;
        r->abandoned = true;
        if (!r->done) { r->done = true; r->ok = false; }
    }
    for (FileReq *f = c->freqs; f; f = f->next) if (!f->done) { f->done = true; f->ok = false; }
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mu);

    if (unlock && cl->canLockClipData) {
        CLIPRDR_UNLOCK_CLIPBOARD_DATA u = {0};
        u.common.msgType = CB_UNLOCK_CLIPDATA;
        u.clipDataId = oldLock;
        cl->ServerUnlockClipboardData(cl, &u);
    }

    free(c->cfmts);
    c->cfmts = (RDPClipFormat *)calloc(list->numFormats ? list->numFormats : 1, sizeof(RDPClipFormat));
    c->ncfmts = 0;
    uint32_t filesId = 0;
    if (c->cfmts) {
        for (UINT32 i = 0; i < list->numFormats; i++) {
            RDPClipFormat *f = &c->cfmts[c->ncfmts++];
            f->id = list->formats[i].formatId;
            if (list->formats[i].formatName)
                snprintf(f->name, sizeof(f->name), "%s", list->formats[i].formatName);
            if (!strcmp(f->name, RDP_FMT_NAME_FILES)) filesId = f->id;
        }
    }

    if (filesId && cl->streamFileClipEnabled) {
        /* Lock the client's data first so a later copy cannot change the file list
         * under a multi-minute paste, then fetch the descriptors. */
        if (cl->canLockClipData) {
            CLIPRDR_LOCK_CLIPBOARD_DATA l = {0};
            l.common.msgType = CB_LOCK_CLIPDATA;
            l.clipDataId = (UINT32)gen;
            if (cl->ServerLockClipboardData(cl, &l) == CHANNEL_RC_OK) {
                pthread_mutex_lock(&c->mu);
                c->lockSent = true; c->lockId = (uint32_t)gen; c->lockGen = gen;
                pthread_mutex_unlock(&c->mu);
            }
        }
        DataReq *r = (DataReq *)calloc(1, sizeof(*r));
        if (r) {
            r->refs = 1; r->formatId = filesId; r->gen = gen; r->internal = true;
            pthread_mutex_lock(&c->mu);
            if (c->reqTail) c->reqTail->next = r; else c->reqHead = r;
            c->reqTail = r;
            pthread_mutex_unlock(&c->mu);
            pump_requests(c);
            return CHANNEL_RC_OK;
        }
    }
    notify_host_client(c, gen, NULL, 0);
    return CHANNEL_RC_OK;
}

static UINT cb_client_format_data_response(CliprdrServerContext *cl,
                                           const CLIPRDR_FORMAT_DATA_RESPONSE *resp) {
    RDPClipboard *c = (RDPClipboard *)cl->custom;
    bool okFlag = (resp->common.msgFlags & CB_RESPONSE_OK) && !(resp->common.msgFlags & CB_RESPONSE_FAIL);
    rdp_verbose("clipboard: <- FormatDataResponse (flags=0x%04x len=%u)",
                resp->common.msgFlags, resp->common.dataLen);

    pthread_mutex_lock(&c->mu);
    DataReq *r = c->reqHead;
    if (!r || !r->sent) {
        pthread_mutex_unlock(&c->mu);
        rdp_verbose("clipboard: unsolicited FormatDataResponse ignored");
        return CHANNEL_RC_OK;
    }
    c->reqHead = r->next;
    if (!c->reqHead) c->reqTail = NULL;
    bool abandoned = r->abandoned;
    bool internal = r->internal;
    uint64_t gen = r->gen;
    pthread_mutex_unlock(&c->mu);

    uint8_t *copy = NULL;
    size_t n = resp->common.dataLen;
    if (okFlag && !abandoned && n <= MAX_CLIENT_PAYLOAD) {
        copy = (uint8_t *)malloc(n ? n : 1);
        if (copy && n) memcpy(copy, resp->requestedFormatData, n);
    }
    bool ok = copy != NULL;

    if (internal) {
        if (!abandoned) descriptors_arrived(c, gen, ok, copy, n);
        free(copy);
        pthread_mutex_lock(&c->mu);
        req_unref_locked(r);
        pthread_mutex_unlock(&c->mu);
    } else {
        pthread_mutex_lock(&c->mu);
        if (!r->done) {
            r->ok = ok; r->data = copy; r->len = n; r->done = true;
            copy = NULL;
        }
        pthread_cond_broadcast(&c->cv);
        req_unref_locked(r);        /* the queue's reference */
        pthread_mutex_unlock(&c->mu);
        free(copy);
    }
    pump_requests(c);
    return CHANNEL_RC_OK;
}

/* ── Mac -> Windows: serving the client's requests ────────────────────────── */

typedef enum { T_FORMAT, T_FILE_SIZE, T_FILE_RANGE } TaskType;

typedef struct {
    RDPClipboard *c;
    TaskType      type;
    uint32_t      kind;
    uint64_t      gen, token;
    RDPFileSet   *set;
    CLIPRDR_FILE_CONTENTS_REQUEST req;
} Task;

static void respond_format_data(RDPClipboard *c, uint64_t gen, bool checkGen, bool ok,
                                const uint8_t *data, size_t len) {
    if (!use_begin(c)) return;
    if (ok && checkGen) {
        pthread_mutex_lock(&c->mu);
        if (c->ownGen != gen) ok = false;        /* a newer advertise superseded this one */
        pthread_mutex_unlock(&c->mu);
    }
    if (len > 0x7FFFFFF0u) ok = false;
    CLIPRDR_FORMAT_DATA_RESPONSE r = {0};
    r.common.msgType  = CB_FORMAT_DATA_RESPONSE;
    r.common.msgFlags = ok ? CB_RESPONSE_OK : CB_RESPONSE_FAIL;
    r.common.dataLen  = ok ? (UINT32)len : 0;
    r.requestedFormatData = (ok && len) ? data : kDummy;
    pthread_mutex_lock(&c->ctx->xportLock);
    UINT rc = c->cliprdr->ServerFormatDataResponse(c->cliprdr, &r);
    pthread_mutex_unlock(&c->ctx->xportLock);
    rdp_verbose("clipboard: -> FormatDataResponse %s len=%zu rc=%u", ok ? "OK" : "FAIL", ok ? len : 0, rc);
    use_end(c);
}

static void respond_file_contents(RDPClipboard *c, uint32_t streamId, bool ok,
                                  const uint8_t *data, uint32_t len) {
    if (!use_begin(c)) return;
    CLIPRDR_FILE_CONTENTS_RESPONSE r = {0};
    r.common.msgType  = CB_FILECONTENTS_RESPONSE;
    r.common.msgFlags = ok ? CB_RESPONSE_OK : CB_RESPONSE_FAIL;
    r.streamId    = streamId;
    r.cbRequested = ok ? len : 0;
    r.requestedData = (ok && len) ? data : kDummy;
    r.common.dataLen = 4 + r.cbRequested;
    pthread_mutex_lock(&c->ctx->xportLock);
    UINT rc = c->cliprdr->ServerFileContentsResponse(c->cliprdr, &r);
    pthread_mutex_unlock(&c->ctx->xportLock);
    if (rc != CHANNEL_RC_OK) rdp_verbose("clipboard: FileContentsResponse send rc=%u", rc);
    use_end(c);
}

static void task_run(void *arg) {
    Task *t = (Task *)arg;
    RDPClipboard *c = t->c;
    pthread_mutex_lock(&c->mu);
    bool closed = c->closed;
    pthread_mutex_unlock(&c->mu);
    if (!closed) {
        switch (t->type) {
        case T_FORMAT: {
            uint8_t *data = NULL; size_t len = 0; bool ok = false;
            if (t->kind == RDP_CLIP_KIND_FILES) {
                ok = t->set && rdp_fileset_serialize(t->set, &data, &len);
                respond_format_data(c, t->gen, false, ok, data, len);
            } else {
                RDPClipHost h;
                if (host_enter(c, &h)) {
                    if (h.render) data = h.render(h.user, t->kind, t->token, &len);
                    host_leave(c);
                }
                ok = data != NULL;
                respond_format_data(c, t->gen, true, ok, data, len);
            }
            free(data);
            break;
        }
        case T_FILE_SIZE: {
            uint64_t sz = 0;
            bool ok = t->set && rdp_fileset_size(t->set, t->req.listIndex, &sz);
            uint8_t b[8];
            for (int i = 0; i < 8; i++) b[i] = (uint8_t)(sz >> (8 * i));
            respond_file_contents(c, t->req.streamId, ok, b, 8);
            break;
        }
        case T_FILE_RANGE: {
            uint64_t pos = ((uint64_t)t->req.nPositionHigh << 32) | t->req.nPositionLow;
            uint32_t want = t->req.cbRequested;
            bool ok = t->set && want <= MAX_RANGE_REQUEST;
            uint8_t *buf = NULL;
            ssize_t got = -1;
            if (ok) {
                buf = (uint8_t *)malloc(want ? want : 1);
                ok = buf != NULL;
            }
            if (ok) { got = rdp_fileset_read(t->set, t->req.listIndex, pos, buf, want); ok = got >= 0; }
            respond_file_contents(c, t->req.streamId, ok, buf, ok ? (uint32_t)got : 0);
            free(buf);
            break;
        }
        }
    }
    rdp_fileset_release(t->set);
    free(t);
    rdp_clip_release(c);
}

static void enqueue_task(RDPClipboard *c, Task *t) {
    t->c = rdp_clip_retain(c);
    dispatch_async_f(c->q, t, task_run);
}

static UINT cb_client_format_data_request(CliprdrServerContext *cl,
                                          const CLIPRDR_FORMAT_DATA_REQUEST *req) {
    RDPClipboard *c = (RDPClipboard *)cl->custom;
    uint32_t id = req->requestedFormatId;
    pthread_mutex_lock(&c->mu);
    uint32_t kind = kind_for_id(c->ownKinds, id);
    Task *t = kind ? (Task *)calloc(1, sizeof(Task)) : NULL;
    if (t) {
        t->type = T_FORMAT; t->kind = kind; t->gen = c->ownGen; t->token = c->ownToken;
        t->set = rdp_fileset_retain(c->ownFiles);
    }
    pthread_mutex_unlock(&c->mu);
    rdp_verbose("clipboard: <- FormatDataRequest 0x%x (%s)", id, t ? "serving" : "refused");
    if (!t) {
        CLIPRDR_FORMAT_DATA_RESPONSE r = {0};
        r.common.msgType = CB_FORMAT_DATA_RESPONSE;
        r.common.msgFlags = CB_RESPONSE_FAIL;
        r.requestedFormatData = kDummy;
        cl->ServerFormatDataResponse(cl, &r);
        return CHANNEL_RC_OK;
    }
    enqueue_task(c, t);
    return CHANNEL_RC_OK;
}

static UINT cb_client_file_contents_request(CliprdrServerContext *cl,
                                            const CLIPRDR_FILE_CONTENTS_REQUEST *req) {
    RDPClipboard *c = (RDPClipboard *)cl->custom;
    pthread_mutex_lock(&c->mu);
    RDPFileSet *set = fileset_for_lock_locked(c, req->haveClipDataId, req->clipDataId);
    pthread_mutex_unlock(&c->mu);
    Task *t = set ? (Task *)calloc(1, sizeof(Task)) : NULL;
    bool isSize = (req->dwFlags & FILECONTENTS_SIZE) != 0;
    bool isRange = (req->dwFlags & FILECONTENTS_RANGE) != 0;
    if (!t || (isSize == isRange)) {
        free(t);
        rdp_fileset_release(set);
        CLIPRDR_FILE_CONTENTS_RESPONSE r = {0};
        r.common.msgType = CB_FILECONTENTS_RESPONSE;
        r.common.msgFlags = CB_RESPONSE_FAIL;
        r.common.dataLen = 4;
        r.streamId = req->streamId;
        r.requestedData = kDummy;
        cl->ServerFileContentsResponse(cl, &r);
        return CHANNEL_RC_OK;
    }
    t->type = isSize ? T_FILE_SIZE : T_FILE_RANGE;
    t->req = *req;
    t->set = set;
    rdp_debug("clipboard: <- FileContentsRequest stream=%u idx=%u %s pos=%u:%u len=%u",
              req->streamId, req->listIndex, isSize ? "SIZE" : "RANGE",
              req->nPositionHigh, req->nPositionLow, req->cbRequested);
    enqueue_task(c, t);
    return CHANNEL_RC_OK;
}

static UINT cb_client_lock(CliprdrServerContext *cl, const CLIPRDR_LOCK_CLIPBOARD_DATA *l) {
    RDPClipboard *c = (RDPClipboard *)cl->custom;
    pthread_mutex_lock(&c->mu);
    if (c->ownFiles) {
        int slot = -1;
        for (int i = 0; i < MAX_LOCKS; i++) if (!c->locks[i].used) { slot = i; break; }
        if (slot < 0) {                         /* evict the oldest */
            slot = c->lockNext++ % MAX_LOCKS;
            rdp_fileset_release(c->locks[slot].set);
        }
        c->locks[slot].used = true;
        c->locks[slot].id = l->clipDataId;
        c->locks[slot].set = rdp_fileset_retain(c->ownFiles);
    }
    pthread_mutex_unlock(&c->mu);
    rdp_verbose("clipboard: <- LockClipboardData id=%u", l->clipDataId);
    return CHANNEL_RC_OK;
}

static UINT cb_client_unlock(CliprdrServerContext *cl, const CLIPRDR_UNLOCK_CLIPBOARD_DATA *u) {
    RDPClipboard *c = (RDPClipboard *)cl->custom;
    pthread_mutex_lock(&c->mu);
    for (int i = 0; i < MAX_LOCKS; i++)
        if (c->locks[i].used && c->locks[i].id == u->clipDataId) {
            rdp_fileset_release(c->locks[i].set);
            c->locks[i].used = false; c->locks[i].set = NULL;
        }
    pthread_mutex_unlock(&c->mu);
    rdp_verbose("clipboard: <- UnlockClipboardData id=%u", u->clipDataId);
    return CHANNEL_RC_OK;
}

/* ── Windows -> Mac file contents ─────────────────────────────────────────── */

static UINT cb_client_file_contents_response(CliprdrServerContext *cl,
                                             const CLIPRDR_FILE_CONTENTS_RESPONSE *resp) {
    RDPClipboard *c = (RDPClipboard *)cl->custom;
    bool ok = (resp->common.msgFlags & CB_RESPONSE_OK) && !(resp->common.msgFlags & CB_RESPONSE_FAIL) &&
              resp->common.dataLen >= 4 && resp->cbRequested == resp->common.dataLen - 4 &&
              resp->cbRequested <= MAX_RANGE_REQUEST * 2;
    uint8_t *copy = NULL;
    if (ok) {
        copy = (uint8_t *)malloc(resp->cbRequested ? resp->cbRequested : 1);
        if (copy && resp->cbRequested) memcpy(copy, resp->requestedData, resp->cbRequested);
        ok = copy != NULL;
    }
    pthread_mutex_lock(&c->mu);
    FileReq *f = c->freqs;
    while (f && f->streamId != resp->streamId) f = f->next;
    if (f && !f->done) {
        f->ok = ok; f->data = copy; f->len = ok ? resp->cbRequested : 0; f->done = true;
        copy = NULL;
        pthread_cond_broadcast(&c->cv);
    }
    pthread_mutex_unlock(&c->mu);
    free(copy);
    return CHANNEL_RC_OK;
}

typedef struct { RDPClipboard *c; uint64_t gen; } FetchCtx;

/* RDPFileFetchFn: one FILECONTENTS request, blocking. Any thread, no xportLock. */
static bool fetch_contents(void *user, uint32_t listIndex, bool sizeOnly, uint64_t pos,
                           uint32_t len, uint8_t *buf, uint32_t *got, uint64_t *sizeOut) {
    FetchCtx *fc = (FetchCtx *)user;
    RDPClipboard *c = fc->c;
    FileReq *f = (FileReq *)calloc(1, sizeof(*f));
    if (!f) return false;
    bool haveLock;
    uint32_t lockId;
    pthread_mutex_lock(&c->mu);
    if (c->closed || c->clientGen != fc->gen) { pthread_mutex_unlock(&c->mu); free(f); return false; }
    f->streamId = ++c->nextStream;
    f->next = c->freqs;
    c->freqs = f;
    haveLock = c->lockSent && c->lockGen == fc->gen;
    lockId = c->lockId;
    pthread_mutex_unlock(&c->mu);

    bool sent = false;
    if (use_begin(c)) {
        CLIPRDR_FILE_CONTENTS_REQUEST r = {0};
        r.common.msgType = CB_FILECONTENTS_REQUEST;
        r.streamId = f->streamId;
        r.listIndex = listIndex;
        r.dwFlags = sizeOnly ? FILECONTENTS_SIZE : FILECONTENTS_RANGE;
        r.nPositionLow = sizeOnly ? 0 : (UINT32)pos;
        r.nPositionHigh = sizeOnly ? 0 : (UINT32)(pos >> 32);
        r.cbRequested = sizeOnly ? 8 : len;
        r.haveClipDataId = haveLock;
        r.clipDataId = lockId;
        pthread_mutex_lock(&c->ctx->xportLock);
        sent = c->cliprdr->ServerFileContentsRequest(c->cliprdr, &r) == CHANNEL_RC_OK;
        pthread_mutex_unlock(&c->ctx->xportLock);
        use_end(c);
    }

    bool ok = false;
    pthread_mutex_lock(&c->mu);
    uint64_t deadline = now_ms() + FILE_CHUNK_TIMEOUT_MS;
    while (sent && !f->done && !c->closed) {
        if (!cv_wait_until(c, deadline)) break;
    }
    if (f->done && f->ok) {
        if (sizeOnly) {
            if (f->len >= 8 && sizeOut) {
                uint64_t v = 0;
                for (int i = 0; i < 8; i++) v |= (uint64_t)f->data[i] << (8 * i);
                *sizeOut = v; ok = true;
            }
        } else {
            uint32_t n = f->len < len ? f->len : len;
            if (n) memcpy(buf, f->data, n);
            if (got) *got = n;
            ok = true;
        }
    }
    FileReq **pp = &c->freqs;
    while (*pp && *pp != f) pp = &(*pp)->next;
    if (*pp) *pp = f->next;
    pthread_mutex_unlock(&c->mu);
    free(f->data);
    free(f);
    return ok;
}

uint8_t *rdp_clip_fetch_format(RDPClipboard *c, uint64_t gen, uint32_t formatId, size_t *len) {
    if (!c || !len) return NULL;
    DataReq *r = (DataReq *)calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->refs = 2;                    /* queue + this waiter */
    r->formatId = formatId;
    r->gen = gen;
    pthread_mutex_lock(&c->mu);
    if (c->closed || c->clientGen != gen) { pthread_mutex_unlock(&c->mu); free(r); return NULL; }
    if (c->reqTail) c->reqTail->next = r; else c->reqHead = r;
    c->reqTail = r;
    pthread_mutex_unlock(&c->mu);

    if (use_begin(c)) {
        pthread_mutex_lock(&c->ctx->xportLock);
        pump_requests(c);
        pthread_mutex_unlock(&c->ctx->xportLock);
        use_end(c);
    }

    uint8_t *out = NULL;
    pthread_mutex_lock(&c->mu);
    uint64_t deadline = now_ms() + FETCH_TIMEOUT_MS;
    while (!r->done && !c->closed) {
        if (!cv_wait_until(c, deadline)) break;
    }
    if (r->done && r->ok) {
        out = r->data; *len = r->len; r->data = NULL;
    } else {
        r->abandoned = true;        /* a late response is discarded by the pump */
        if (!r->done) rdp_verbose("clipboard: fetch of format 0x%x timed out / aborted", formatId);
    }
    req_unref_locked(r);
    pthread_mutex_unlock(&c->mu);
    return out;
}

char *rdp_clip_fetch_file(RDPClipboard *c, uint64_t gen, uint32_t topOrdinal, const char *destRoot) {
    if (!c) return NULL;
    pthread_mutex_lock(&c->mu);
    ClientFiles *cf = (!c->closed && c->clientGen == gen) ? c->cfiles : NULL;
    if (cf) cf->refs++;
    pthread_mutex_unlock(&c->mu);
    if (!cf) { rdp_verbose("clipboard: file fetch for stale/unknown generation %llu", (unsigned long long)gen); return NULL; }

    uint32_t tops[4096];
    uint32_t nt = rdp_clipfiles_top_entries(cf->d, cf->n, tops, 4096);
    char *path = NULL;
    if (topOrdinal < nt && topOrdinal < 4096) {
        FetchCtx fc = { c, gen };
        const char *err = NULL;
        path = rdp_clipfiles_download(cf->d, cf->n, tops[topOrdinal], destRoot, fetch_contents, &fc,
                                      &c->abortFlag, &err);
        if (!path) rdp_error("clipboard: file download failed: %s", err ? err : "unknown");
        else rdp_verbose("clipboard: downloaded '%s'", path);
    }
    pthread_mutex_lock(&c->mu);
    client_files_unref_locked(cf);
    pthread_mutex_unlock(&c->mu);
    return path;
}

/* ── host-facing control ──────────────────────────────────────────────────── */

void rdp_clip_set_host(RDPClipboard *c, const RDPClipHost *host) {
    if (!c) return;
    pthread_mutex_lock(&c->mu);
    if (host) { c->host = *host; c->hostSet = true; }
    else {
        c->hostSet = false;
        while (c->hostUsers > 0) pthread_cond_wait(&c->cv, &c->mu);
    }
    pthread_mutex_unlock(&c->mu);
}

bool rdp_clip_advertise(RDPClipboard *c, uint32_t kinds, uint64_t token,
                        const char *const *paths, size_t nPaths) {
    if (!c) return false;
    RDPFileSet *fs = NULL;
    if (kinds & RDP_CLIP_KIND_FILES) {
        bool huge = true;
        pthread_mutex_lock(&c->mu);
        if (!c->closed && c->cliprdr) huge = !c->capsSeen || c->cliprdr->hasHugeFileSupport;
        pthread_mutex_unlock(&c->mu);
        if (c->wantFiles && nPaths) fs = rdp_fileset_create(paths, nPaths, huge);
        if (!fs) kinds &= ~RDP_CLIP_KIND_FILES;
    }
    pthread_mutex_lock(&c->mu);
    if (c->closed) { pthread_mutex_unlock(&c->mu); rdp_fileset_release(fs); return false; }
    rdp_fileset_release(c->ownFiles);
    c->ownFiles = fs;
    c->ownKinds = kinds;
    c->ownToken = token;
    c->ownGen++;
    c->ownAdvertisedAt = now_ms();
    c->ownPending = kinds != 0;
    pthread_mutex_unlock(&c->mu);
    rdp_verbose("clipboard: Mac copy -> advertise kinds=0x%x token=%llu", kinds, (unsigned long long)token);
    flush_advertise(c);
    return true;
}

/* ── lifecycle ────────────────────────────────────────────────────────────── */

RDPClipboard *rdp_clip_retain(RDPClipboard *c) {
    if (c) __atomic_add_fetch(&c->refs, 1, __ATOMIC_RELAXED);
    return c;
}

static void clip_free(RDPClipboard *c) {
    for (DataReq *r = c->reqHead; r;) { DataReq *n = r->next; free(r->data); free(r); r = n; }
    for (FileReq *f = c->freqs; f;) { FileReq *n = f->next; free(f->data); free(f); f = n; }
    client_files_unref_locked(c->cfiles);
    rdp_fileset_release(c->ownFiles);
    for (int i = 0; i < MAX_LOCKS; i++) if (c->locks[i].used) rdp_fileset_release(c->locks[i].set);
    free(c->cfmts);
    if (c->q) dispatch_release(c->q);
    pthread_cond_destroy(&c->cv);
    pthread_mutex_destroy(&c->mu);
    free(c);
}

void rdp_clip_release(RDPClipboard *c) {
    if (!c) return;
    if (__atomic_sub_fetch(&c->refs, 1, __ATOMIC_ACQ_REL) == 0) clip_free(c);
}

static void noop_task(void *p) { (void)p; }

void rdp_clip_destroy(RDPClipboard *c) {
    if (!c) return;
    pthread_mutex_lock(&c->mu);
    c->closed = true;
    c->abortFlag = 1;
    c->hostSet = false;
    pthread_cond_broadcast(&c->cv);              /* wake every waiter: they fail */
    while (c->users > 0 || c->hostUsers > 0) pthread_cond_wait(&c->cv, &c->mu);
    pthread_mutex_unlock(&c->mu);
    dispatch_sync_f(c->q, NULL, noop_task);      /* drain queued tasks (they see `closed`) */
    if (c->cliprdr) { cliprdr_server_context_free(c->cliprdr); c->cliprdr = NULL; }
    c->ctx = NULL;
    rdp_clip_release(c);
}

void *rdp_clip_event(RDPClipboard *c) {
    return (c && c->cliprdr) ? c->cliprdr->GetEventHandle(c->cliprdr) : NULL;
}

void rdp_clip_pump(RDPClipboard *c) {
    if (!c || !use_begin(c)) return;
    HANDLE ev = c->cliprdr->GetEventHandle(c->cliprdr);
    /* One PDU per CheckEventHandle; drain a burst so large file transfers (many
     * 1 MB responses) are not throttled to one PDU per 50 ms loop iteration. */
    for (int i = 0; ev && i < 32; i++) {
        if (WaitForSingleObject(ev, 0) != WAIT_OBJECT_0) break;
        UINT rc = c->cliprdr->CheckEventHandle(c->cliprdr);
        if (rc != CHANNEL_RC_OK) { rdp_verbose("clipboard read failed: %u", rc); break; }
    }
    /* A copy made before the handshake finished is flushed here (not from inside
     * a callback: advertising from FreeRDP's receive dispatch re-enters it). */
    flush_advertise(c);
    pump_requests(c);
    use_end(c);
}

static bool env_on(const char *name) {
    const char *v = getenv(name);
    return !(v && v[0] == '0');
}

RDPClipboard *rdp_clip_create(RDPPeerContext *ctx) {
    RDPClipboard *c = (RDPClipboard *)calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->refs = 1;
    c->ctx = ctx;
    pthread_mutex_init(&c->mu, NULL);
    pthread_cond_init(&c->cv, NULL);
    c->q = dispatch_queue_create("com.macosrdp.clipboard", DISPATCH_QUEUE_SERIAL);
    c->wantFiles = env_on("RDP_CLIP_FILES");
    c->wantLock  = env_on("RDP_CLIP_LOCK");

    c->cliprdr = cliprdr_server_context_new(ctx->vcm);
    if (!c->cliprdr) { rdp_error("cliprdr_server_context_new failed"); clip_free(c); return NULL; }
    CliprdrServerContext *cl = c->cliprdr;
    cl->custom      = c;
    cl->rdpcontext  = &ctx->base;
    /* Our feature offer; FreeRDP narrows these by the client's capabilities. */
    cl->useLongFormatNames   = TRUE;
    cl->streamFileClipEnabled = c->wantFiles;
    cl->fileClipNoFilePaths   = c->wantFiles;
    cl->canLockClipData       = c->wantFiles && c->wantLock;
    cl->hasHugeFileSupport    = c->wantFiles;
    /* Register EVERY inbound callback before Open() so no client PDU is dropped. */
    cl->ClientCapabilities       = cb_client_capabilities;
    cl->ClientFormatList         = cb_client_format_list;
    cl->ClientFormatListResponse = cb_client_format_list_response;
    cl->ClientFormatDataRequest  = cb_client_format_data_request;
    cl->ClientFormatDataResponse = cb_client_format_data_response;
    cl->ClientFileContentsRequest  = cb_client_file_contents_request;
    cl->ClientFileContentsResponse = cb_client_file_contents_response;
    cl->ClientLockClipboardData    = cb_client_lock;
    cl->ClientUnlockClipboardData  = cb_client_unlock;

    if (cl->Open(cl) != CHANNEL_RC_OK) {
        rdp_verbose("clipboard channel open failed");
        cliprdr_server_context_free(cl);
        c->cliprdr = NULL;
        clip_free(c);
        return NULL;
    }

    /* The channel is pumped by the shared VCM loop, not cliprdr's own Start()
     * thread, so the server-init handshake is never sent automatically. */
    UINT32 gf = CB_USE_LONG_FORMAT_NAMES;
    if (cl->streamFileClipEnabled) gf |= CB_STREAM_FILECLIP_ENABLED;
    if (cl->fileClipNoFilePaths)   gf |= CB_FILECLIP_NO_FILE_PATHS;
    if (cl->canLockClipData)       gf |= CB_CAN_LOCK_CLIPDATA;
    if (cl->hasHugeFileSupport)    gf |= CB_HUGE_FILE_SUPPORT_ENABLED;
    CLIPRDR_GENERAL_CAPABILITY_SET general = {
        .capabilitySetType   = CB_CAPSTYPE_GENERAL,
        .capabilitySetLength = CB_CAPSTYPE_GENERAL_LEN,
        .version             = CB_CAPS_VERSION_2,
        .generalFlags        = gf,
    };
    CLIPRDR_CAPABILITIES caps = {
        .common = { .msgType = CB_CLIP_CAPS, .msgFlags = 0, .dataLen = 4 + CB_CAPSTYPE_GENERAL_LEN },
        .cCapabilitiesSets = 1,
        .capabilitySets = (CLIPRDR_CAPABILITY_SET *)&general,
    };
    CLIPRDR_MONITOR_READY ready = { .common = { .msgType = CB_MONITOR_READY } };
    UINT cc = cl->ServerCapabilities(cl, &caps);
    UINT mr = cl->MonitorReady(cl, &ready);
    rdp_verbose("clipboard channel opened (flags=0x%x caps=%u monitor-ready=%u)", gf, cc, mr);
    return c;
}
