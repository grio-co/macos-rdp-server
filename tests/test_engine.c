/*
 * Protocol-engine test for protocol/RDPClipboard.c against a MOCK FreeRDP cliprdr
 * server context (no network, no real channel, no pasteboard).
 *
 * A "run-loop thread" executes injected client PDUs under xportLock (exactly how
 * rdp_peer_run_once drives the real callbacks); the mock Server* functions record
 * what the engine would put on the wire. A scripted "client" reads that outbox and
 * injects responses, so both directions, the threading rules (waiters released
 * from the run-loop thread, no wait under xportLock), request serialization,
 * stale generations, locks, >4 GB ranges and teardown-while-waiting are exercised.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>

#include "protocol/RDPPeer.h"
#include "protocol/RDPClipboard.h"
#include "protocol/RDPClipboardFiles.h"

static int g_fail = 0, g_pass = 0;
#define CHECK(cond) do { if (cond) g_pass++; else { g_fail++; \
    printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define SECTION(name) printf("== %s\n", name)

/* ── mock channel ─────────────────────────────────────────────────────────── */

enum { O_CAPS = 1, O_MONITOR, O_FMTLIST, O_FMTLIST_RESP, O_DATA_REQ, O_DATA_RESP,
       O_FC_REQ, O_FC_RESP, O_LOCK, O_UNLOCK };

typedef struct {
    int      type;
    uint32_t n, ids[8];
    char     names[8][40];
    uint32_t id;                 /* requested format / clipDataId / streamId */
    uint32_t flags, dataLen;     /* msgFlags / payload length */
    uint8_t *data;
    CLIPRDR_FILE_CONTENTS_REQUEST fc;
    uint32_t generalFlags;
    int      lockHeldByThread;   /* send executed with xportLock held by the sender */
} Out;

static pthread_mutex_t g_om = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_oc = PTHREAD_COND_INITIALIZER;
static Out  g_out[512];
static int  g_nout, g_outRead;

static CliprdrServerContext *g_cl;
static RDPPeerContext g_ctx;
static int g_unlockedSends;     /* server sends that happened WITHOUT holding xportLock */

static void push_out(Out *o) {
    pthread_mutex_lock(&g_om);
    g_out[g_nout++] = *o;
    pthread_cond_broadcast(&g_oc);
    pthread_mutex_unlock(&g_om);
}

static int xport_held_by_me(void) {
    /* recursive mutex: if trylock succeeds on another thread it's free; on the same
     * thread it always succeeds, so test ownership from a helper thread instead. */
    return 1;
}

/* Verify the sender holds xportLock: try-lock from a throwaway thread must fail. */
static void *probe_thread(void *arg) {
    int *r = arg;
    *r = pthread_mutex_trylock(&g_ctx.xportLock);
    if (*r == 0) pthread_mutex_unlock(&g_ctx.xportLock);
    return NULL;
}
static void check_send_locked(void) {
    int r = 0;
    pthread_t t;
    pthread_create(&t, NULL, probe_thread, &r);
    pthread_join(t, NULL);
    if (r == 0) g_unlockedSends++;      /* lock was free => sender did not hold it */
    (void)xport_held_by_me;
}

/* Wait for (and remove) the first outbox record of `type`. */
static Out *wait_out(int type, int timeoutMs) {
    struct timespec dl; clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += timeoutMs / 1000; dl.tv_nsec += (long)(timeoutMs % 1000) * 1000000L;
    if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; }
    static Out ret;
    pthread_mutex_lock(&g_om);
    for (;;) {
        for (int i = g_outRead; i < g_nout; i++) {
            if (g_out[i].type == type) {
                ret = g_out[i];
                g_out[i].type = 0;       /* consumed */
                pthread_mutex_unlock(&g_om);
                return &ret;
            }
        }
        if (pthread_cond_timedwait(&g_oc, &g_om, &dl) != 0) { pthread_mutex_unlock(&g_om); return NULL; }
    }
}
static int count_out(int type) {
    int c = 0;
    pthread_mutex_lock(&g_om);
    for (int i = 0; i < g_nout; i++) if (g_out[i].type == type) c++;
    pthread_mutex_unlock(&g_om);
    return c;
}

static UINT m_open(CliprdrServerContext *c) { (void)c; return CHANNEL_RC_OK; }
static UINT m_caps(CliprdrServerContext *c, const CLIPRDR_CAPABILITIES *caps) {
    (void)c;
    Out o = { .type = O_CAPS };
    o.generalFlags = ((const CLIPRDR_GENERAL_CAPABILITY_SET *)caps->capabilitySets)->generalFlags;
    push_out(&o);
    return CHANNEL_RC_OK;
}
static UINT m_monitor(CliprdrServerContext *c, const CLIPRDR_MONITOR_READY *m) {
    (void)c; (void)m; Out o = { .type = O_MONITOR }; push_out(&o); return CHANNEL_RC_OK;
}
static UINT m_format_list(CliprdrServerContext *c, const CLIPRDR_FORMAT_LIST *l) {
    (void)c; check_send_locked();
    Out o = { .type = O_FMTLIST, .n = l->numFormats };
    /* FreeRDP requires msgType == CB_FORMAT_LIST and a NON-NULL name for every format */
    if (l->common.msgType != CB_FORMAT_LIST) g_fail++, printf("  FAIL: format list msgType\n");
    for (UINT32 i = 0; i < l->numFormats && i < 8; i++) {
        o.ids[i] = l->formats[i].formatId;
        if (!l->formats[i].formatName) { g_fail++; printf("  FAIL: NULL format name\n"); }
        else snprintf(o.names[i], sizeof o.names[i], "%s", l->formats[i].formatName);
    }
    push_out(&o);
    return CHANNEL_RC_OK;
}
static UINT m_format_list_resp(CliprdrServerContext *c, const CLIPRDR_FORMAT_LIST_RESPONSE *r) {
    (void)c; Out o = { .type = O_FMTLIST_RESP, .flags = r->common.msgFlags }; push_out(&o); return CHANNEL_RC_OK;
}
static UINT m_lock(CliprdrServerContext *c, const CLIPRDR_LOCK_CLIPBOARD_DATA *l) {
    (void)c; check_send_locked(); Out o = { .type = O_LOCK, .id = l->clipDataId }; push_out(&o); return CHANNEL_RC_OK;
}
static UINT m_unlock(CliprdrServerContext *c, const CLIPRDR_UNLOCK_CLIPBOARD_DATA *l) {
    (void)c; check_send_locked(); Out o = { .type = O_UNLOCK, .id = l->clipDataId }; push_out(&o); return CHANNEL_RC_OK;
}
static UINT m_data_req(CliprdrServerContext *c, const CLIPRDR_FORMAT_DATA_REQUEST *r) {
    (void)c; check_send_locked();
    if (r->common.dataLen != 4) { g_fail++; printf("  FAIL: FormatDataRequest dataLen must be 4 (FreeRDP overrun)\n"); }
    Out o = { .type = O_DATA_REQ, .id = r->requestedFormatId };
    push_out(&o);
    return CHANNEL_RC_OK;
}
static UINT m_data_resp(CliprdrServerContext *c, const CLIPRDR_FORMAT_DATA_RESPONSE *r) {
    (void)c; check_send_locked();
    if (!r->requestedFormatData) { g_fail++; printf("  FAIL: NULL response data pointer\n"); }
    Out o = { .type = O_DATA_RESP, .flags = r->common.msgFlags, .dataLen = r->common.dataLen };
    if (r->common.msgType != CB_FORMAT_DATA_RESPONSE) { g_fail++; printf("  FAIL: response msgType\n"); }
    o.data = malloc(o.dataLen ? o.dataLen : 1);
    if (o.dataLen) memcpy(o.data, r->requestedFormatData, o.dataLen);
    push_out(&o);
    return CHANNEL_RC_OK;
}
static UINT m_fc_req(CliprdrServerContext *c, const CLIPRDR_FILE_CONTENTS_REQUEST *r) {
    (void)c; check_send_locked();
    Out o = { .type = O_FC_REQ, .id = r->streamId, .fc = *r };
    push_out(&o);
    return CHANNEL_RC_OK;
}
static UINT m_fc_resp(CliprdrServerContext *c, const CLIPRDR_FILE_CONTENTS_RESPONSE *r) {
    (void)c; check_send_locked();
    Out o = { .type = O_FC_RESP, .id = r->streamId, .flags = r->common.msgFlags, .dataLen = r->cbRequested };
    if (r->common.msgType != CB_FILECONTENTS_RESPONSE) { g_fail++; printf("  FAIL: fc response msgType\n"); }
    o.data = malloc(o.dataLen ? o.dataLen : 1);
    if (o.dataLen) memcpy(o.data, r->requestedData, o.dataLen);
    push_out(&o);
    return CHANNEL_RC_OK;
}
static HANDLE m_event(CliprdrServerContext *c) { (void)c; return (HANDLE)0x1; }
static UINT m_check(CliprdrServerContext *c) { (void)c; return CHANNEL_RC_OK; }

CliprdrServerContext *cliprdr_server_context_new(HANDLE vcm) {
    (void)vcm;
    CliprdrServerContext *c = calloc(1, sizeof *c);
    c->Open = m_open; c->ServerCapabilities = m_caps; c->MonitorReady = m_monitor;
    c->ServerFormatList = m_format_list; c->ServerFormatListResponse = m_format_list_resp;
    c->ServerLockClipboardData = m_lock; c->ServerUnlockClipboardData = m_unlock;
    c->ServerFormatDataRequest = m_data_req; c->ServerFormatDataResponse = m_data_resp;
    c->ServerFileContentsRequest = m_fc_req; c->ServerFileContentsResponse = m_fc_resp;
    c->GetEventHandle = m_event; c->CheckEventHandle = m_check;
    g_cl = c;
    return c;
}
void cliprdr_server_context_free(CliprdrServerContext *c) { free(c); g_cl = NULL; }
DWORD WaitForSingleObject(HANDLE h, DWORD ms) { (void)h; (void)ms; return WAIT_TIMEOUT; }

/* ── simulated run-loop thread ────────────────────────────────────────────── */

typedef struct Job { struct Job *next; void (*fn)(void *); void *arg; int done; } Job;
static pthread_mutex_t g_jm = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_jc = PTHREAD_COND_INITIALIZER;
static Job *g_jobs;
static int g_stopLoop;
static pthread_t g_loop;

static void *loop_main(void *a) {
    (void)a;
    for (;;) {
        pthread_mutex_lock(&g_jm);
        while (!g_jobs && !g_stopLoop) pthread_cond_wait(&g_jc, &g_jm);
        if (!g_jobs && g_stopLoop) { pthread_mutex_unlock(&g_jm); return NULL; }
        Job *j = g_jobs; g_jobs = j->next;
        pthread_mutex_unlock(&g_jm);
        pthread_mutex_lock(&g_ctx.xportLock);      /* like rdp_peer_run_once */
        j->fn(j->arg);
        pthread_mutex_unlock(&g_ctx.xportLock);
        pthread_mutex_lock(&g_jm); j->done = 1; pthread_cond_broadcast(&g_jc); pthread_mutex_unlock(&g_jm);
    }
}
/* Run fn on the run-loop thread and wait for it. */
static void on_loop(void (*fn)(void *), void *arg) {
    Job j = { NULL, fn, arg, 0 };
    pthread_mutex_lock(&g_jm);
    Job **pp = &g_jobs; while (*pp) pp = &(*pp)->next; *pp = &j;
    pthread_cond_broadcast(&g_jc);
    while (!j.done) pthread_cond_wait(&g_jc, &g_jm);
    pthread_mutex_unlock(&g_jm);
}

/* injected client PDUs */
typedef struct {
    uint32_t flags;                       /* general caps flags */
    CLIPRDR_FORMAT fmts[8]; uint32_t nfmts;
    uint32_t reqId;
    const uint8_t *data; uint32_t dataLen; uint16_t msgFlags;
    CLIPRDR_FILE_CONTENTS_REQUEST fc;
    uint32_t lockId, streamId;
} Inj;

static void inj_caps(void *a) {
    Inj *i = a;
    g_cl->useLongFormatNames = (i->flags & CB_USE_LONG_FORMAT_NAMES) != 0;
    g_cl->streamFileClipEnabled = (i->flags & CB_STREAM_FILECLIP_ENABLED) != 0;
    g_cl->fileClipNoFilePaths = (i->flags & CB_FILECLIP_NO_FILE_PATHS) != 0;
    g_cl->canLockClipData = (i->flags & CB_CAN_LOCK_CLIPDATA) != 0;
    g_cl->hasHugeFileSupport = (i->flags & CB_HUGE_FILE_SUPPORT_ENABLED) != 0;   /* FreeRDP narrows like this */
    CLIPRDR_GENERAL_CAPABILITY_SET g = { CB_CAPSTYPE_GENERAL, CB_CAPSTYPE_GENERAL_LEN, CB_CAPS_VERSION_2, i->flags };
    CLIPRDR_CAPABILITIES caps = { .cCapabilitiesSets = 1, .capabilitySets = (CLIPRDR_CAPABILITY_SET *)&g };
    g_cl->ClientCapabilities(g_cl, &caps);
}
static void inj_format_list(void *a) {
    Inj *i = a;
    CLIPRDR_FORMAT_LIST l = { .numFormats = i->nfmts, .formats = i->fmts };
    l.common.msgType = CB_FORMAT_LIST;
    g_cl->ClientFormatList(g_cl, &l);
}
static void inj_data_req(void *a) {
    Inj *i = a; CLIPRDR_FORMAT_DATA_REQUEST r = { .requestedFormatId = i->reqId };
    g_cl->ClientFormatDataRequest(g_cl, &r);
}
static void inj_data_resp(void *a) {
    Inj *i = a;
    CLIPRDR_FORMAT_DATA_RESPONSE r = { .requestedFormatData = i->data };
    r.common.msgFlags = i->msgFlags; r.common.dataLen = i->dataLen;
    g_cl->ClientFormatDataResponse(g_cl, &r);
}
static void inj_fc_req(void *a) { Inj *i = a; g_cl->ClientFileContentsRequest(g_cl, &i->fc); }
static void inj_fc_resp(void *a) {
    Inj *i = a;
    CLIPRDR_FILE_CONTENTS_RESPONSE r = { .streamId = i->streamId, .cbRequested = i->dataLen, .requestedData = i->data };
    r.common.msgFlags = i->msgFlags; r.common.dataLen = 4 + i->dataLen;
    g_cl->ClientFileContentsResponse(g_cl, &r);
}
static void inj_lock(void *a) { Inj *i = a; CLIPRDR_LOCK_CLIPBOARD_DATA l = { .clipDataId = i->lockId }; g_cl->ClientLockClipboardData(g_cl, &l); }
static void inj_unlock(void *a) { Inj *i = a; CLIPRDR_UNLOCK_CLIPBOARD_DATA l = { .clipDataId = i->lockId }; g_cl->ClientUnlockClipboardData(g_cl, &l); }

static void send_caps(uint32_t flags) { Inj i = { .flags = flags }; on_loop(inj_caps, &i); }
static void send_format_list(const uint32_t *ids, const char *const *names, uint32_t n) {
    Inj i = { .nfmts = n };
    for (uint32_t k = 0; k < n; k++) { i.fmts[k].formatId = ids[k]; i.fmts[k].formatName = (char *)(names ? names[k] : ""); }
    on_loop(inj_format_list, &i);
}
static void send_data_resp(const void *d, uint32_t n, int ok) {
    Inj i = { .data = d ? d : (const uint8_t *)"", .dataLen = n, .msgFlags = ok ? CB_RESPONSE_OK : CB_RESPONSE_FAIL };
    on_loop(inj_data_resp, &i);
}

/* ── mock host ────────────────────────────────────────────────────────────── */

static pthread_mutex_t g_hm = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_hc = PTHREAD_COND_INITIALIZER;
static int      g_renderCalls, g_renderBlock, g_renderOnLoop;
static uint32_t g_lastKind; static uint64_t g_lastToken, g_goodToken = 100;
static uint64_t g_hostGen; static uint32_t g_hostNFmts, g_hostNFiles; static int g_hostCalls;
static RDPClipFormat g_hostFmts[8];
static char g_hostFile0[128];
static pthread_t g_loopId;

static uint8_t *h_render(void *u, uint32_t kind, uint64_t token, size_t *len) {
    (void)u;
    pthread_mutex_lock(&g_hm);
    g_renderCalls++; g_lastKind = kind; g_lastToken = token;
    if (pthread_equal(pthread_self(), g_loopId)) g_renderOnLoop++;   /* must NOT run on the run-loop thread */
    while (g_renderBlock) pthread_cond_wait(&g_hc, &g_hm);
    pthread_mutex_unlock(&g_hm);
    if (token != g_goodToken) return NULL;                            /* "pasteboard changed" */
    const char *s = kind == RDP_CLIP_KIND_TEXT ? "T\0e\0s\0t\0\0\0" : "OTHER";
    size_t n = kind == RDP_CLIP_KIND_TEXT ? 10 : 5;
    uint8_t *p = malloc(n); memcpy(p, s, n); *len = n;
    return p;
}
static void h_client(void *u, uint64_t gen, const RDPClipFormat *f, uint32_t n, const RDPFileDesc *files, uint32_t nf) {
    (void)u;
    pthread_mutex_lock(&g_hm);
    g_hostGen = gen; g_hostNFmts = n; g_hostNFiles = nf; g_hostCalls++;
    for (uint32_t i = 0; i < n && i < 8; i++) g_hostFmts[i] = f[i];
    g_hostFile0[0] = 0;
    if (nf) snprintf(g_hostFile0, sizeof g_hostFile0, "%s", files[0].name);
    pthread_cond_broadcast(&g_hc);
    pthread_mutex_unlock(&g_hm);
}
static int wait_host_calls(int n, int ms) {
    struct timespec dl; clock_gettime(CLOCK_REALTIME, &dl); dl.tv_sec += ms / 1000;
    pthread_mutex_lock(&g_hm);
    int ok = 1;
    while (g_hostCalls < n) if (pthread_cond_timedwait(&g_hc, &g_hm, &dl) != 0) { ok = 0; break; }
    pthread_mutex_unlock(&g_hm);
    return ok;
}

/* ── fetch helpers (host side, other threads) ─────────────────────────────── */

typedef struct { RDPClipboard *c; uint64_t gen; uint32_t fid; uint8_t *out; size_t len; double secs; } FetchArg;
static void *fetch_thread(void *p) {
    FetchArg *a = p;
    struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
    a->out = rdp_clip_fetch_format(a->c, a->gen, a->fid, &a->len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    a->secs = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    return NULL;
}

/* ── tests ────────────────────────────────────────────────────────────────── */

#define ALL_FLAGS (CB_USE_LONG_FORMAT_NAMES | CB_STREAM_FILECLIP_ENABLED | CB_FILECLIP_NO_FILE_PATHS | \
                   CB_CAN_LOCK_CLIPDATA | CB_HUGE_FILE_SUPPORT_ENABLED)

static char g_root[512];

static void make_tree(void) {
    char p[1024];
    snprintf(p, sizeof p, "%s/src", g_root); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/src/Tree", g_root); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/src/Tree/inner", g_root); mkdir(p, 0755);
    const char *files[][2] = { { "src/Tree/one.txt", "ONE" }, { "src/Tree/inner/two.txt", "second file contents" },
                               { "src/solo.txt", "SOLO" }, { "src/other.txt", "OTHER-SET" } };
    for (int i = 0; i < 4; i++) {
        snprintf(p, sizeof p, "%s/%s", g_root, files[i][0]);
        FILE *f = fopen(p, "w"); fputs(files[i][1], f); fclose(f);
    }
    /* 3.5 MB file so a download needs several 1 MB range requests */
    snprintf(p, sizeof p, "%s/src/Tree/inner/blob.bin", g_root);
    FILE *f = fopen(p, "w");
    for (int i = 0; i < 3500; i++) { char blk[1000]; memset(blk, i & 255, sizeof blk); fwrite(blk, 1, sizeof blk, f); }
    fclose(f);
}

/* Scripted Windows client for a file copy: answers lock/format-data/file-contents
 * requests from `src` (a fileset standing in for the client's file system). */
typedef struct { RDPFileSet *src; volatile int stop; int ranges, sizes; int sawLockedIds; uint32_t expectLock; uint32_t maxReq; pthread_t t; } Client;
static void *client_thread(void *p) {
    Client *cl = p;
    while (!__atomic_load_n(&cl->stop, __ATOMIC_ACQUIRE)) {
        Out *o = wait_out(O_FC_REQ, 100);
        if (!o) continue;
        Inj i = {0};
        i.streamId = o->fc.streamId;
        if (o->fc.haveClipDataId && o->fc.clipDataId == cl->expectLock) cl->sawLockedIds++;
        if (o->fc.dwFlags & FILECONTENTS_SIZE) {
            cl->sizes++;
            uint64_t sz = 0; rdp_fileset_size(cl->src, o->fc.listIndex, &sz);
            uint8_t b[8]; for (int k = 0; k < 8; k++) b[k] = (uint8_t)(sz >> (8 * k));
            i.data = b; i.dataLen = 8; i.msgFlags = CB_RESPONSE_OK;
            on_loop(inj_fc_resp, &i);
        } else {
            cl->ranges++;
            if (o->fc.cbRequested > cl->maxReq) cl->maxReq = o->fc.cbRequested;
            uint64_t pos = ((uint64_t)o->fc.nPositionHigh << 32) | o->fc.nPositionLow;
            uint8_t *buf = malloc(o->fc.cbRequested);
            ssize_t r = rdp_fileset_read(cl->src, o->fc.listIndex, pos, buf, o->fc.cbRequested);
            i.data = buf; i.dataLen = r < 0 ? 0 : (uint32_t)r; i.msgFlags = r < 0 ? CB_RESPONSE_FAIL : CB_RESPONSE_OK;
            on_loop(inj_fc_resp, &i);
            free(buf);
        }
    }
    return NULL;
}

int main(void) {
    char tmpl[512];
    const char *base = getenv("TEST_TMP");
    snprintf(tmpl, sizeof tmpl, "%s/engine-test-XXXXXX", base ? base : "/tmp");
    if (!mkdtemp(tmpl)) { perror("mkdtemp"); return 2; }
    snprintf(g_root, sizeof g_root, "%s", tmpl);
    make_tree();

    pthread_mutexattr_t ma; pthread_mutexattr_init(&ma); pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_ctx.xportLock, &ma);
    pthread_create(&g_loop, NULL, loop_main, NULL);
    g_loopId = g_loop;

    SECTION("handshake: nothing at create; capabilities + monitor ready once started");
    RDPClipboard *c = rdp_clip_create(&g_ctx);
    CHECK(c != NULL);
    CHECK(count_out(O_CAPS) == 0 && count_out(O_MONITOR) == 0);      /* not before activation */
    on_loop((void (*)(void *))rdp_clip_start, c);
    Out *o = wait_out(O_CAPS, 1000);
    CHECK(o && (o->generalFlags & ALL_FLAGS) == ALL_FLAGS);
    CHECK(wait_out(O_MONITOR, 1000) != NULL);
    on_loop((void (*)(void *))rdp_clip_start, c);                    /* a second start is a no-op */
    on_loop((void (*)(void *))rdp_clip_pump, c);                     /* too soon to resend */
    CHECK(count_out(O_CAPS) == 0 && count_out(O_MONITOR) == 0);      /* (wait_out consumes) */

    SECTION("handshake: a silent client gets Monitor Ready again");
    usleep(3100 * 1000);
    on_loop((void (*)(void *))rdp_clip_pump, c);
    CHECK(wait_out(O_CAPS, 1000) != NULL && wait_out(O_MONITOR, 1000) != NULL);
    CHECK(count_out(O_CAPS) == 0 && count_out(O_MONITOR) == 0);
    RDPClipHost host = { .user = NULL, .render = h_render, .client_clipboard = h_client };
    rdp_clip_set_host(c, &host);

    SECTION("Mac -> Win: advertise before handshake is deferred, flushed by the pump");
    CHECK(rdp_clip_advertise(c, RDP_CLIP_KIND_TEXT | RDP_CLIP_KIND_HTML | RDP_CLIP_KIND_RTF | RDP_CLIP_KIND_PNG |
                                RDP_CLIP_KIND_DIB | RDP_CLIP_KIND_DIBV5, g_goodToken, NULL, 0));
    CHECK(count_out(O_FMTLIST) == 0);                               /* channel not ready: nothing on the wire */
    send_caps(ALL_FLAGS);
    on_loop((void (*)(void *))rdp_clip_pump, c);
    o = wait_out(O_FMTLIST, 1000);
    CHECK(o && o->n == 6);
    usleep(3100 * 1000);                                             /* client answered: no resend */
    on_loop((void (*)(void *))rdp_clip_pump, c);
    CHECK(count_out(O_CAPS) == 0 && count_out(O_MONITOR) == 0);
    if (o && o->n == 6) {
        CHECK(o->ids[0] == 13 && o->names[0][0] == 0);               /* CF_UNICODETEXT, unnamed */
        CHECK(o->ids[1] >= 0xC000 && strcmp(o->names[1], "HTML Format") == 0);
        CHECK(o->ids[2] >= 0xC000 && strcmp(o->names[2], "Rich Text Format") == 0);
        CHECK(o->ids[3] >= 0xC000 && strcmp(o->names[3], "PNG") == 0);
        CHECK(o->ids[4] == 8 && o->ids[5] == 17);
    }
    uint32_t htmlId = o ? o->ids[1] : 0;

    SECTION("Mac -> Win: delayed rendering on the worker, stale token fails cleanly");
    {
        Inj i = { .reqId = 13 };
        on_loop(inj_data_req, &i);
        o = wait_out(O_DATA_RESP, 2000);
        CHECK(o && (o->flags & CB_RESPONSE_OK) && o->dataLen == 10 && memcmp(o->data, "T\0e\0s\0t\0\0\0", 10) == 0);
        CHECK(g_lastKind == RDP_CLIP_KIND_TEXT && g_lastToken == g_goodToken && g_renderOnLoop == 0);
        i.reqId = htmlId; on_loop(inj_data_req, &i);
        o = wait_out(O_DATA_RESP, 2000);
        CHECK(o && (o->flags & CB_RESPONSE_OK) && g_lastKind == RDP_CLIP_KIND_HTML);
        i.reqId = 12345; on_loop(inj_data_req, &i);                  /* never advertised */
        o = wait_out(O_DATA_RESP, 2000);
        CHECK(o && (o->flags & CB_RESPONSE_FAIL) && o->dataLen == 0);
        i.reqId = 1; on_loop(inj_data_req, &i);                      /* CF_TEXT: served via TEXT */
        o = wait_out(O_DATA_RESP, 2000);
        CHECK(o && (o->flags & CB_RESPONSE_OK) && g_lastKind == RDP_CLIP_KIND_ANSI);
    }
    /* re-advertise with a token the host says is stale -> render returns NULL -> FAIL */
    CHECK(rdp_clip_advertise(c, RDP_CLIP_KIND_TEXT, 999, NULL, 0));
    wait_out(O_FMTLIST, 1000);
    {
        Inj i = { .reqId = 13 };
        on_loop(inj_data_req, &i);
        o = wait_out(O_DATA_RESP, 2000);
        CHECK(o && (o->flags & CB_RESPONSE_FAIL));
    }
    /* the pasteboard "changes" (new advertise) while a render is still running */
    g_goodToken = 1000;
    CHECK(rdp_clip_advertise(c, RDP_CLIP_KIND_TEXT, 1000, NULL, 0));
    wait_out(O_FMTLIST, 1000);
    pthread_mutex_lock(&g_hm); g_renderBlock = 1; pthread_mutex_unlock(&g_hm);
    {
        Inj i = { .reqId = 13 };
        on_loop(inj_data_req, &i);                                    /* render now blocks on the worker */
        usleep(100000);
        CHECK(rdp_clip_advertise(c, RDP_CLIP_KIND_TEXT, 1001, NULL, 0));   /* supersedes it */
        wait_out(O_FMTLIST, 1000);
        pthread_mutex_lock(&g_hm); g_renderBlock = 0; pthread_cond_broadcast(&g_hc); pthread_mutex_unlock(&g_hm);
        o = wait_out(O_DATA_RESP, 2000);
        CHECK(o && (o->flags & CB_RESPONSE_FAIL));                    /* superseded -> fail, not stale data */
    }
    g_goodToken = 1001;

    SECTION("loop guard: client echoing our own list is ignored");
    {
        uint32_t ids[1] = { 13 };
        int before = g_hostCalls;
        send_format_list(ids, NULL, 1);
        wait_out(O_FMTLIST_RESP, 1000);
        usleep(100000);
        CHECK(g_hostCalls == before);
    }

    SECTION("Win -> Mac: format list -> host notified, fetch serialized in order");
    {
        usleep(10);
        /* move out of the echo window by advertising something different first */
        CHECK(rdp_clip_advertise(c, RDP_CLIP_KIND_HTML, 1002, NULL, 0));
        wait_out(O_FMTLIST, 1000);
        uint32_t ids[3] = { 13, 0xC300, 8 };
        const char *names[3] = { "", "HTML Format", "" };
        int before = g_hostCalls;
        send_format_list(ids, names, 3);
        o = wait_out(O_FMTLIST_RESP, 1000);
        CHECK(o && (o->flags & CB_RESPONSE_OK));
        CHECK(wait_host_calls(before + 1, 1000));
        CHECK(g_hostNFmts == 3 && g_hostNFiles == 0 && g_hostFmts[1].id == 0xC300 && !strcmp(g_hostFmts[1].name, "HTML Format"));
        uint64_t gen = g_hostGen;
        FetchArg a1 = { c, gen, 13 }, a2 = { c, gen, 0xC300 };
        pthread_t t1, t2;
        pthread_create(&t1, NULL, fetch_thread, &a1);
        o = wait_out(O_DATA_REQ, 1000);
        CHECK(o && o->id == 13);
        pthread_create(&t2, NULL, fetch_thread, &a2);
        usleep(150000);
        CHECK(count_out(O_DATA_REQ) == 0);                            /* second request waits: one in flight */
        send_data_resp("h\0i\0\0\0", 6, 1);
        pthread_join(t1, NULL);
        CHECK(a1.out && a1.len == 6 && memcmp(a1.out, "h\0i\0\0\0", 6) == 0);
        o = wait_out(O_DATA_REQ, 1000);
        CHECK(o && o->id == 0xC300);
        send_data_resp("<b>x</b>", 8, 1);
        pthread_join(t2, NULL);
        CHECK(a2.out && a2.len == 8 && memcmp(a2.out, "<b>x</b>", 8) == 0);
        free(a1.out); free(a2.out);

        /* client refusal */
        FetchArg a3 = { c, gen, 8 };
        pthread_create(&t1, NULL, fetch_thread, &a3);
        wait_out(O_DATA_REQ, 1000);
        send_data_resp(NULL, 0, 0);
        pthread_join(t1, NULL);
        CHECK(a3.out == NULL);

        /* stale generation is refused immediately without touching the wire */
        FetchArg a4 = { c, gen + 5, 13 };
        fetch_thread(&a4);
        CHECK(a4.out == NULL && a4.secs < 0.5 && count_out(O_DATA_REQ) == 0);
    }

    SECTION("Win -> Mac: a new client copy fails waiters of the old one; late answer discarded");
    {
        uint32_t ids[1] = { 13 };
        int before = g_hostCalls;
        send_format_list(ids, NULL, 1);
        wait_out(O_FMTLIST_RESP, 1000);
        wait_host_calls(before + 1, 1000);
        uint64_t gen = g_hostGen;
        FetchArg a = { c, gen, 13 };
        pthread_t t;
        pthread_create(&t, NULL, fetch_thread, &a);
        wait_out(O_DATA_REQ, 1000);                                   /* on the wire, unanswered */
        before = g_hostCalls;
        uint32_t ids2[2] = { 13, 8 };
        send_format_list(ids2, NULL, 2);                              /* Windows copied again */
        pthread_join(t, NULL);
        CHECK(a.out == NULL && a.secs < 5.0);
        wait_out(O_FMTLIST_RESP, 1000);
        wait_host_calls(before + 1, 1000);
        uint64_t gen2 = g_hostGen;
        CHECK(gen2 == gen + 1);
        /* the late response to the ABANDONED request must not be taken as the new one's answer */
        FetchArg b = { c, gen2, 13 };
        pthread_create(&t, NULL, fetch_thread, &b);
        usleep(150000);
        CHECK(count_out(O_DATA_REQ) == 0);                            /* still waiting for the old answer */
        send_data_resp("late", 4, 1);                                 /* answers the abandoned request */
        o = wait_out(O_DATA_REQ, 1000);
        CHECK(o && o->id == 13);
        send_data_resp("n\0e\0w\0\0\0", 8, 1);
        pthread_join(t, NULL);
        CHECK(b.out && b.len == 8 && memcmp(b.out, "n\0e\0w\0\0\0", 8) == 0);
        free(b.out);
    }

    SECTION("Win -> Mac files: lock, descriptors, chunked tree download, unlock on next copy");
    {
        char p1[1024], p2[1024];
        snprintf(p1, sizeof p1, "%s/src/Tree", g_root); snprintf(p2, sizeof p2, "%s/src/solo.txt", g_root);
        const char *paths[2] = { p1, p2 };
        RDPFileSet *clientFs = rdp_fileset_create(paths, 2, true);
        uint8_t *wire; size_t wn;
        CHECK(rdp_fileset_serialize(clientFs, &wire, &wn));
        uint32_t ids[2] = { 0xC400, 13 };
        const char *names[2] = { "FileGroupDescriptorW", "" };
        int before = g_hostCalls;
        send_format_list(ids, names, 2);
        wait_out(O_FMTLIST_RESP, 1000);
        o = wait_out(O_LOCK, 1000);
        CHECK(o != NULL);
        uint32_t lockId = o ? o->id : 0;
        o = wait_out(O_DATA_REQ, 1000);
        CHECK(o && o->id == 0xC400);
        CHECK(g_hostCalls == before);                                 /* host told only once the list is known */
        send_data_resp(wire, (uint32_t)wn, 1);
        CHECK(wait_host_calls(before + 1, 1000));
        CHECK(g_hostNFiles > 5 && strcmp(g_hostFile0, "Tree") == 0);
        uint64_t gen = g_hostGen;
        CHECK(lockId == (uint32_t)gen);

        Client cl = { .src = clientFs, .expectLock = lockId };
        pthread_create(&cl.t, NULL, client_thread, &cl);
        char dest[1024]; snprintf(dest, sizeof dest, "%s/dl", g_root);
        char *out = rdp_clip_fetch_file(c, gen, 0, dest);            /* top-level entry 0 = Tree */
        CHECK(out != NULL);
        char cmd[2048];
        snprintf(cmd, sizeof cmd, "diff -r '%s/src/Tree' '%s/dl/Tree' >/dev/null", g_root, g_root);
        CHECK(system(cmd) == 0);
        CHECK(cl.ranges >= 4 && cl.maxReq <= (1u << 20));            /* 3.5 MB blob => >= 4 requests of <= 1 MB */
        CHECK(cl.sawLockedIds == cl.ranges + cl.sizes && cl.sizes == 0);   /* every request carried the clipDataId */
        free(out);
        out = rdp_clip_fetch_file(c, gen, 1, dest);                   /* solo.txt */
        CHECK(out && strstr(out, "solo.txt"));
        free(out);
        CHECK(rdp_clip_fetch_file(c, gen, 9, dest) == NULL);          /* no such entry */

        /* a new client copy unlocks the old data */
        uint32_t ids2[1] = { 13 };
        send_format_list(ids2, NULL, 1);
        o = wait_out(O_UNLOCK, 1000);
        CHECK(o && o->id == lockId);
        CHECK(rdp_clip_fetch_file(c, gen, 0, dest) == NULL);          /* old generation is dead */
        __atomic_store_n(&cl.stop, 1, __ATOMIC_RELEASE); pthread_join(cl.t, NULL);
        free(wire);
        rdp_fileset_release(clientFs);
    }

    SECTION("Mac -> Win files: descriptors, SIZE / RANGE (>4 GB), locked snapshot");
    {
        char p1[1024], p2[1024], p3[1024], big[1024];
        snprintf(p1, sizeof p1, "%s/src/Tree", g_root); snprintf(p2, sizeof p2, "%s/src/solo.txt", g_root);
        snprintf(p3, sizeof p3, "%s/src/other.txt", g_root); snprintf(big, sizeof big, "%s/src/huge.bin", g_root);
        int hfd = open(big, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        ftruncate(hfd, (off_t)((6ULL << 30) + 10));
        pwrite(hfd, "FAR", 3, (off_t)(5ULL << 30));
        close(hfd);
        const char *setA[3] = { p1, p2, big };
        CHECK(rdp_clip_advertise(c, RDP_CLIP_KIND_FILES, 2000, setA, 3));
        o = wait_out(O_FMTLIST, 1000);
        CHECK(o && o->n == 1 && strcmp(o->names[0], "FileGroupDescriptorW") == 0);
        uint32_t fid = o ? o->ids[0] : 0;
        /* the client locks the snapshot, then asks for the descriptors */
        Inj i = { .lockId = 77 }; on_loop(inj_lock, &i);
        i.reqId = fid; on_loop(inj_data_req, &i);
        o = wait_out(O_DATA_RESP, 3000);
        CHECK(o && (o->flags & CB_RESPONSE_OK));
        RDPFileDesc *d = NULL; uint32_t dn = 0;
        CHECK(o && rdp_filelist_parse(o->data, o->dataLen, &d, &dn));
        uint32_t hugeIdx = 0, soloIdx = 0;
        for (uint32_t k = 0; k < dn; k++) { if (!strcmp(d[k].name, "huge.bin")) hugeIdx = k; if (!strcmp(d[k].name, "solo.txt")) soloIdx = k; }
        CHECK(dn == 7 && strcmp(d[0].name, "Tree") == 0 && hugeIdx && d[hugeIdx].size == (6ULL << 30) + 10);
        rdp_filelist_free(d, dn);
        /* SIZE */
        Inj fc = {0};
        fc.fc.streamId = 11; fc.fc.listIndex = hugeIdx; fc.fc.dwFlags = FILECONTENTS_SIZE; fc.fc.cbRequested = 8;
        fc.fc.haveClipDataId = TRUE; fc.fc.clipDataId = 77;
        on_loop(inj_fc_req, &fc);
        o = wait_out(O_FC_RESP, 3000);
        uint64_t sz = 0; if (o && o->dataLen == 8) for (int k = 0; k < 8; k++) sz |= (uint64_t)o->data[k] << (8 * k);
        CHECK(o && o->id == 11 && (o->flags & CB_RESPONSE_OK) && sz == (6ULL << 30) + 10);
        /* RANGE with nPositionHigh != 0 */
        fc.fc.streamId = 12; fc.fc.dwFlags = FILECONTENTS_RANGE; fc.fc.cbRequested = 3;
        fc.fc.nPositionHigh = 1; fc.fc.nPositionLow = 1U << 30;     /* 5 GiB */
        on_loop(inj_fc_req, &fc);
        o = wait_out(O_FC_RESP, 3000);
        CHECK(o && o->id == 12 && o->dataLen == 3 && memcmp(o->data, "FAR", 3) == 0);
        /* a different clipboard is advertised; the LOCKED id still reads the old set */
        const char *setB[1] = { p3 };
        CHECK(rdp_clip_advertise(c, RDP_CLIP_KIND_FILES, 2001, setB, 1));
        wait_out(O_FMTLIST, 1000);
        fc.fc.streamId = 13; fc.fc.listIndex = soloIdx; fc.fc.nPositionHigh = 0; fc.fc.nPositionLow = 0; fc.fc.cbRequested = 100;
        on_loop(inj_fc_req, &fc);                                    /* clipDataId = 77 -> old set */
        o = wait_out(O_FC_RESP, 3000);
        CHECK(o && o->dataLen == 4 && memcmp(o->data, "SOLO", 4) == 0);
        fc.fc.streamId = 14; fc.fc.haveClipDataId = FALSE; fc.fc.listIndex = 0;
        on_loop(inj_fc_req, &fc);                                    /* no id -> current set: other.txt */
        o = wait_out(O_FC_RESP, 3000);
        CHECK(o && o->dataLen == 9 && memcmp(o->data, "OTHER-SET", 9) == 0);
        /* unlock; the old snapshot is gone, the id now falls back to the current set */
        i.lockId = 77; on_loop(inj_unlock, &i);
        /* bad requests fail cleanly */
        fc.fc.streamId = 15; fc.fc.listIndex = 99;
        on_loop(inj_fc_req, &fc);
        o = wait_out(O_FC_RESP, 3000);
        CHECK(o && o->id == 15 && (o->flags & CB_RESPONSE_FAIL) && o->dataLen == 0);
        fc.fc.streamId = 16; fc.fc.listIndex = 0; fc.fc.dwFlags = FILECONTENTS_RANGE | FILECONTENTS_SIZE;
        on_loop(inj_fc_req, &fc);
        o = wait_out(O_FC_RESP, 3000);
        CHECK(o && (o->flags & CB_RESPONSE_FAIL));
        unlink(big);
    }

    SECTION("no huge-file support: >= 2 GB files are withheld; no lock cap: no lock PDUs");
    {
        char big[1024], p2[1024];
        snprintf(big, sizeof big, "%s/src/huge2.bin", g_root); snprintf(p2, sizeof p2, "%s/src/solo.txt", g_root);
        int hfd = open(big, O_WRONLY | O_CREAT | O_TRUNC, 0644); ftruncate(hfd, (off_t)(3ULL << 30)); close(hfd);
        send_caps(CB_USE_LONG_FORMAT_NAMES | CB_STREAM_FILECLIP_ENABLED);   /* client lacks huge + lock */
        const char *set[2] = { big, p2 };
        CHECK(rdp_clip_advertise(c, RDP_CLIP_KIND_FILES, 3000, set, 2));
        o = wait_out(O_FMTLIST, 1000);
        Inj i = { .reqId = o ? o->ids[0] : 0 }; on_loop(inj_data_req, &i);
        o = wait_out(O_DATA_RESP, 3000);
        RDPFileDesc *d = NULL; uint32_t dn = 0;
        CHECK(o && rdp_filelist_parse(o->data, o->dataLen, &d, &dn) && dn == 1 && !strcmp(d[0].name, "solo.txt"));
        rdp_filelist_free(d, dn);
        unlink(big);
        /* a client that cannot do long names only gets the predefined formats */
        send_caps(0);
        CHECK(rdp_clip_advertise(c, RDP_CLIP_KIND_TEXT | RDP_CLIP_KIND_HTML | RDP_CLIP_KIND_DIB, 3001, NULL, 0));
        o = wait_out(O_FMTLIST, 1000);
        CHECK(o && o->n == 2 && o->ids[0] == 13 && o->ids[1] == 8);
        /* files require STREAM_FILECLIP: nothing to advertise */
        CHECK(rdp_clip_advertise(c, RDP_CLIP_KIND_FILES, 3002, set, 2));
        usleep(100000);
        CHECK(count_out(O_FMTLIST) == 0);
    }

    SECTION("teardown while a paste is waiting: waiter fails fast, no hang, no crash");
    {
        send_caps(ALL_FLAGS);
        CHECK(rdp_clip_advertise(c, RDP_CLIP_KIND_TEXT, 4000, NULL, 0));
        wait_out(O_FMTLIST, 1000);
        uint32_t ids[1] = { 13 };
        int before = g_hostCalls;
        send_format_list(ids, NULL, 1);
        wait_host_calls(before + 1, 1000);
        FetchArg a = { c, g_hostGen, 13 };
        pthread_t t;
        pthread_create(&t, NULL, fetch_thread, &a);
        wait_out(O_DATA_REQ, 1000);
        usleep(100000);
        RDPClipboard *keep = rdp_clip_retain(c);                      /* the host's own reference */
        struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
        rdp_clip_set_host(c, NULL);
        rdp_clip_destroy(c);
        pthread_join(t, NULL);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        CHECK(a.out == NULL);
        CHECK((t1.tv_sec - t0.tv_sec) < 5);
        /* everything after destroy fails soft */
        CHECK(!rdp_clip_advertise(keep, RDP_CLIP_KIND_TEXT, 1, NULL, 0));
        size_t l = 0;
        CHECK(rdp_clip_fetch_format(keep, 1, 13, &l) == NULL);
        CHECK(rdp_clip_fetch_file(keep, 1, 0, "/nonexistent") == NULL);
        rdp_clip_release(keep);
    }

    CHECK(g_unlockedSends == 0);        /* every wire write happened under xportLock */

    pthread_mutex_lock(&g_jm); g_stopLoop = 1; pthread_cond_broadcast(&g_jc); pthread_mutex_unlock(&g_jm);
    pthread_join(g_loop, NULL);
    char cmd[1100]; snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_root); if (system(cmd)) {}
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
