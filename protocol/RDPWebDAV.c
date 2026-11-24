#define __STDC_WANT_LIB_EXT1__ 1   /* memset_s: wipes the compiler keeps */
#define RDP_LOG_COMPONENT "webdav"
#include "logging/RDPLog.h"
#include "protocol/RDPWebDAV.h"
#include "protocol/RDPPeer.h"
#include "protocol/RDPDrivePath.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>

/* POSIX networking */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <strings.h>    /* strncasecmp on macOS */
#include <pwd.h>        /* getpwuid: the home directory under launchd */
#include <signal.h>     /* kill: stop a pending mount_webdav */
#include <sys/mount.h>  /* statfs: is the drive still mounted? */
#include <spawn.h>      /* posix_spawn: helpers get no daemon sockets */

/* FreeRDP / WinPR types needed for rdpContext access */
#include <freerdp/freerdp.h>

/* ── Constants ─────────────────────────────────────────────────────────── */

#define WEBDAV_HDR_MAX      65536          /* request line + headers */
#define WEBDAV_BODY_MAX     (1024 * 1024)  /* non-PUT bodies: read and dropped */
#define WEBDAV_MAX_PATH     4096           /* decoded URL path, bytes */
#define WEBDAV_IO_CHUNK     65536          /* bytes per READ / WRITE IRP */
#define WEBDAV_MAX_ENTRIES  100000         /* directory entries listed per PROPFIND */
#define IRP_TIMEOUT_SEC     30             /* Maximum seconds to wait for an IRP response */
#define WEBDAV_NO_REPLY     0xFFFFFFFFu    /* IRP not sent, or no answer in time */
#define WEBDAV_AUTH_USER    "macrdp"       /* user name half of the drive password */

/* NTSTATUS values from the client (MS-ERREF 2.3). */
#define NT_NO_MORE_FILES          0x80000006u
#define NT_UNSUCCESSFUL           0xC0000001u
#define NT_NO_SUCH_FILE           0xC000000Fu
#define NT_END_OF_FILE            0xC0000011u
#define NT_ACCESS_DENIED          0xC0000022u
#define NT_OBJECT_NAME_INVALID    0xC0000033u
#define NT_OBJECT_NAME_NOT_FOUND  0xC0000034u
#define NT_OBJECT_NAME_COLLISION  0xC0000035u
#define NT_OBJECT_PATH_NOT_FOUND  0xC000003Au
#define NT_SHARING_VIOLATION      0xC0000043u
#define NT_DELETE_PENDING         0xC0000056u
#define NT_DISK_FULL              0xC000007Fu
#define NT_MEDIA_WRITE_PROTECTED  0xC00000A2u
#define NT_FILE_IS_A_DIRECTORY    0xC00000BAu
#define NT_DIRECTORY_NOT_EMPTY    0xC0000101u
#define NT_NOT_A_DIRECTORY        0xC0000103u
#define NT_CANNOT_DELETE          0xC0000121u

/* DR_CREATE_REQ values (MS-SMB2 2.2.13), as Windows servers send them. */
#define WD_LIST_DIRECTORY       0x00000001u   /* FILE_READ_DATA on a directory */
#define WD_DELETE               0x00010000u
#define WD_SYNCHRONIZE          0x00100000u
/* File opens ask for specific rights, as a Windows server's redirector sends them,
 * never GENERIC_READ / GENERIC_WRITE: mstsc opened a file asked for with GENERIC_READ
 * and then refused the read (0xC0000022). FreeRDP's client takes either. */
#define WD_FILE_GENERIC_READ    0x00120089u   /* READ_CONTROL | SYNCHRONIZE | READ_DATA,
                                                 READ_EA, READ_ATTRIBUTES */
#define WD_FILE_GENERIC_WRITE   0x00120116u   /* READ_CONTROL | SYNCHRONIZE | WRITE_DATA,
                                                 APPEND_DATA, WRITE_EA, WRITE_ATTRIBUTES */
#define WD_FILE_OPEN            1u
#define WD_FILE_CREATE          2u
#define WD_FILE_OVERWRITE_IF    5u
#define WD_OPT_DIRECTORY        0x00000001u   /* FILE_DIRECTORY_FILE */
#define WD_OPT_SYNC_IO          0x00000020u   /* FILE_SYNCHRONOUS_IO_NONALERT */
#define WD_OPT_NON_DIRECTORY    0x00000040u   /* FILE_NON_DIRECTORY_FILE */
#define WD_OPT_DELETE_ON_CLOSE  0x00001000u
#define WD_FILE_CREATED         2u            /* DR_CREATE_RSP Information */

/* ── IRP waiter ─────────────────────────────────────────────────────────
 *
 * WebDAV handler threads block on this struct waiting for the run-loop
 * thread to call the IRP completion callback.
 *
 * Locking protocol:
 *   1. WebDAV thread initialises the waiter, acquires xportLock, sends IRP,
 *      releases xportLock, then waits on the cond var.
 *   2. Run-loop thread receives IOCOMPLETION, calls rdpdr_free_request which
 *      calls irp_waiter_cb, which acquires waiter->mu, sets done=true,
 *      copies payload, signals cond var, and releases waiter->mu.
 *   3. WebDAV thread wakes, reads payload, frees it after use.
 */
/*
 * IrpWaiter is heap-allocated so its lifetime can safely outlive the WebDAV
 * handler thread in the case of a timeout.  The `refcount` field (protected
 * by `mu`) starts at 2: one reference for the waiting thread and one for the
 * pending IRP callback.  Whichever side decrements to 0 frees the struct.
 * This eliminates the use-after-free that would occur if the run-loop fires
 * the callback after the waiter has timed out and the handler has returned.
 */
typedef struct {
    pthread_mutex_t  mu;
    pthread_cond_t   cv;
    int              refcount;   /* 2 = both sides live; 1 = one side done */
    bool             done;
    uint32_t         ioStatus;
    uint8_t         *payload;    /* heap copy, freed when refcount reaches 0 */
    uint32_t         payloadLen;
} IrpWaiter;

static IrpWaiter *irp_waiter_alloc(void) {
    IrpWaiter *w = (IrpWaiter *)calloc(1, sizeof(*w));
    if (!w) return NULL;
    pthread_mutex_init(&w->mu, NULL);
    pthread_cond_init(&w->cv, NULL);
    w->refcount = 2;  /* one for waiter, one for callback */
    return w;
}

/* Drop one reference.  When the count reaches 0, free the waiter. */
static void irp_waiter_unref(IrpWaiter *w) {
    pthread_mutex_lock(&w->mu);
    int remaining = --w->refcount;
    pthread_mutex_unlock(&w->mu);
    if (remaining == 0) {
        free(w->payload);
        pthread_cond_destroy(&w->cv);
        pthread_mutex_destroy(&w->mu);
        free(w);
    }
}

/* Callback invoked on the peer run-loop thread. */
static void irp_waiter_cb(uint32_t ioStatus, const uint8_t *payload,
                           uint32_t payloadLen, void *userdata) {
    IrpWaiter *w = (IrpWaiter *)userdata;
    pthread_mutex_lock(&w->mu);
    w->done     = true;
    w->ioStatus = ioStatus;
    if (payloadLen > 0 && payload && !w->payload) {
        w->payload = (uint8_t *)malloc(payloadLen);
        if (w->payload) {
            memcpy(w->payload, payload, payloadLen);
            w->payloadLen = payloadLen;
        }
    }
    pthread_cond_signal(&w->cv);
    pthread_mutex_unlock(&w->mu);
    /* Drop the callback's reference — may free w if waiter timed out. */
    irp_waiter_unref(w);
}

/* Wait for the IRP to complete (with timeout).
 * Returns true if done==true (may still have a non-SUCCESS ioStatus).
 * On return, the caller owns the waiter's reference and must call
 * irp_waiter_unref() when finished reading the result. */
static bool irp_waiter_wait(IrpWaiter *w) {
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += IRP_TIMEOUT_SEC;

    pthread_mutex_lock(&w->mu);
    while (!w->done) {
        int rc = pthread_cond_timedwait(&w->cv, &w->mu, &deadline);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&w->mu);
            /* Drop our reference; callback will clean up when it fires. */
            irp_waiter_unref(w);
            return false;
        }
    }
    pthread_mutex_unlock(&w->mu);
    return true;
}

/* ── Server struct ──────────────────────────────────────────────────────── */

struct RDPWebDAVServer {
    freerdp_peer   *peer;
    uint32_t        deviceId;
    char            driveName[16];   /* DOS name from DEVICE_LIST_ANNOUNCE */
    uint16_t        port;
    int             listenFd;        /* bound TCP socket */
    pthread_t       acceptThread;
    volatile bool   running;
    char            volName[32];     /* RDP-<drive letter>, the Finder name */
    char            mountPoint[1024]; /* ~/RDP-Drives/<drive letter> */
    bool            mounted;         /* set by the mount thread; read after join */
    /* mount_webdav runs on its own thread: its PROPFIND needs IRP replies that
     * only the peer thread receives, so mounting there deadlocked the session. */
    pthread_t       mountThread;
    bool            mountStarted;
    volatile pid_t  mountPid;        /* mount_webdav child while it runs, else 0 */
    bool            loggedList, loggedRead, loggedWrite;  /* first success, logged once */
    /* The drive password: random per drive, handed to mount_webdav through
     * -a <fd> and required on every request, so no other local process can
     * use this port to read or write the client's drive. */
    char            authPass[72];     /* 64 hex digits */
    char            authUserPass[96]; /* "macrdp:<authPass>", what Basic carries */
    bool            loggedBadAuth;
};

/* ── HTTP helpers ───────────────────────────────────────────────────────── */

/* Sends all of buf; false if the client went away. */
static bool http_send(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

/* Sends the status line and headers; contentLength < 0 sends no
 * Content-Length (a chunked body follows). Each connection carries one
 * request: the server closes it after answering. */
static bool http_head(int fd, int status, const char *statusStr,
                      const char *extraHeaders, long long contentLength) {
    char hdr[2048], cl[48] = "";
    if (contentLength >= 0) snprintf(cl, sizeof(cl), "Content-Length: %lld\r\n", contentLength);
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "DAV: 1, 2\r\n"
        "MS-Author-Via: DAV\r\n"
        "Connection: close\r\n"
        "%s%s\r\n",
        status, statusStr, cl, extraHeaders ? extraHeaders : "");
    if (n <= 0 || (size_t)n >= sizeof(hdr)) return false;
    return http_send(fd, hdr, (size_t)n);
}

/* Sends a complete response with an optional body. */
static void http_respond(int fd, int status, const char *statusStr,
                         const char *extraHeaders, const char *body, size_t bodyLen) {
    if (http_head(fd, status, statusStr, extraHeaders, (long long)bodyLen) && body && bodyLen > 0)
        http_send(fd, body, bodyLen);
}

/* ── Little-endian readers ──────────────────────────────────────────────── */

static uint32_t rd32(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}
static uint64_t rd64(const uint8_t *b) {
    return (uint64_t)rd32(b) | ((uint64_t)rd32(b + 4) << 32);
}

/* ── Growing text buffer (PROPFIND and LOCK bodies) ─────────────────────── */

typedef struct { char *buf; size_t len, cap; bool oom; } XmlBuf;

static void xb_printf(XmlBuf *x, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void xb_printf(XmlBuf *x, const char *fmt, ...) {
    if (x->oom) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) { x->oom = true; return; }
    if (x->len + (size_t)n + 1 > x->cap) {
        size_t cap = x->cap ? x->cap : 4096;
        while (x->len + (size_t)n + 1 > cap) cap *= 2;
        char *nb = (char *)realloc(x->buf, cap);
        if (!nb) { x->oom = true; return; }
        x->buf = nb;
        x->cap = cap;
    }
    va_start(ap, fmt);
    vsnprintf(x->buf + x->len, x->cap - x->len, fmt, ap);
    va_end(ap);
    x->len += (size_t)n;
}

/* ── Directory entries ──────────────────────────────────────────────────── */

#define FILE_ATTR_HIDDEN     0x02
#define FILE_ATTR_SYSTEM     0x04
#define FILE_ATTR_DIRECTORY  0x10

typedef struct {
    char     name[1024];     /* UTF-8 */
    uint64_t size;           /* EndOfFile */
    uint64_t lastWrite;      /* FILETIME, 0 = unknown */
    uint32_t attrs;
} DirEntry;

typedef bool (*DirVisitor)(const DirEntry *e, void *ud);   /* false stops */

/* FILE_FULL_DIR_INFORMATION (MS-FSCC 2.4.14): NextEntryOffset(4) FileIndex(4)
 * CreationTime(8) LastAccessTime(8) LastWriteTime(8) ChangeTime(8)
 * EndOfFile(8) AllocationSize(8) FileAttributes(4) FileNameLength(4)
 * EaSize(4) = 68 bytes, then the UTF-16LE name without a NUL. Visits each
 * entry chained by NextEntryOffset. Returns the number of entries, or -1 if
 * the visitor stopped. */
#define FFDI_FIXED_SIZE 68
static int parse_ffdi(const uint8_t *buf, uint32_t len, DirVisitor visit, void *ud) {
    int count = 0;
    uint32_t off = 0;
    while (len >= FFDI_FIXED_SIZE && off <= len - FFDI_FIXED_SIZE) {
        const uint8_t *e = buf + off;
        uint32_t next    = rd32(e);
        uint32_t nameLen = rd32(e + 60);
        if (nameLen > len - off - FFDI_FIXED_SIZE) break;     /* truncated entry */
        count++;
        DirEntry d;
        d.lastWrite = rd64(e + 24);
        d.size      = rd64(e + 40);
        d.attrs     = rd32(e + 56);
        if (rdpdr_utf16le_to_utf8(e + FFDI_FIXED_SIZE, nameLen, d.name, sizeof(d.name)) &&
            d.name[0] && !visit(&d, ud))
            return -1;
        if (next == 0 || next > len - off) break;
        off += next;
    }
    return count;
}

/* Appends one DAV:response. urlPath is decoded; hrefs are percent-encoded,
 * with a trailing '/' for collections. */
static void propfind_append(XmlBuf *x, const char *urlPath, bool isDir,
                            const char *displayName, uint64_t size, uint64_t lastWrite) {
    char href[WEBDAV_MAX_PATH * 3 + 2];
    char name[sizeof(((DirEntry *)0)->name) * 6];
    char date[40];
    if (!rdp_url_path_encode(urlPath, href, sizeof(href) - 1)) return;
    size_t hl = strlen(href);
    if (isDir && (hl == 0 || href[hl - 1] != '/')) { href[hl++] = '/'; href[hl] = '\0'; }
    if (!rdp_xml_escape(displayName, name, sizeof(name))) return;
    rdp_http_date_from_filetime(lastWrite, date, sizeof(date));
    if (isDir)
        xb_printf(x,
            "<D:response><D:href>%s</D:href><D:propstat><D:prop>"
            "<D:displayname>%s</D:displayname>"
            "<D:resourcetype><D:collection/></D:resourcetype>"
            "<D:getlastmodified>%s</D:getlastmodified>"
            "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
            href, name, date);
    else
        xb_printf(x,
            "<D:response><D:href>%s</D:href><D:propstat><D:prop>"
            "<D:displayname>%s</D:displayname>"
            "<D:resourcetype/>"
            "<D:getcontentlength>%llu</D:getcontentlength>"
            "<D:getlastmodified>%s</D:getlastmodified>"
            "<D:getetag>\"%llx-%llx\"</D:getetag>"
            "<D:getcontenttype>application/octet-stream</D:getcontenttype>"
            "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
            href, name, (unsigned long long)size, date,
            (unsigned long long)lastWrite, (unsigned long long)size);
}

/* ── IRP round-trip helpers ─────────────────────────────────────────────── */

/* Send an IRP (under xportLock) then block (without the lock) until the
 * IOCOMPLETION arrives.  Returns the IrpWaiter; caller must call
 * irp_waiter_destroy() after consuming the result. */

typedef bool (*IrpSendFn)(void *args);

/* Arguments for rdpdr_send_create_req via generic trampoline. */
typedef struct {
    RDPPeerContext *ctx;
    uint32_t        deviceId;
    const char     *path;
    uint32_t        desiredAccess;
    uint32_t        createDisposition;
    uint32_t        createOptions;
    IrpWaiter      *waiter;
} CreateArgs;
static bool send_create(void *a) {
    CreateArgs *c = (CreateArgs *)a;
    return rdpdr_send_create_req(c->ctx, c->deviceId, c->path,
                                  c->desiredAccess, c->createDisposition,
                                  c->createOptions,
                                  irp_waiter_cb, c->waiter);
}

typedef struct { RDPPeerContext *ctx; uint32_t devId; uint32_t fid; IrpWaiter *w; } CloseArgs;
static bool send_close(void *a) {
    CloseArgs *c = (CloseArgs *)a;
    return rdpdr_send_close_req(c->ctx, c->devId, c->fid, irp_waiter_cb, c->w);
}

typedef struct { RDPPeerContext *ctx; uint32_t devId; uint32_t fid;
                 uint64_t offset; uint32_t length; IrpWaiter *w; } ReadArgs;
static bool send_read(void *a) {
    ReadArgs *r = (ReadArgs *)a;
    return rdpdr_send_read_req(r->ctx, r->devId, r->fid, r->offset, r->length,
                                irp_waiter_cb, r->w);
}

typedef struct { RDPPeerContext *ctx; uint32_t devId; uint32_t fid;
                 uint64_t offset; const uint8_t *data; uint32_t len; IrpWaiter *w; } WriteArgs;
static bool send_write(void *a) {
    WriteArgs *wr = (WriteArgs *)a;
    return rdpdr_send_write_req(wr->ctx, wr->devId, wr->fid, wr->offset,
                                 wr->data, wr->len, irp_waiter_cb, wr->w);
}

typedef struct { RDPPeerContext *ctx; uint32_t devId; uint32_t fid;
                 const char *pattern; IrpWaiter *w; } QueryDirArgs;
static bool send_query_dir(void *a) {
    QueryDirArgs *q = (QueryDirArgs *)a;
    return rdpdr_send_query_dir_req(q->ctx, q->devId, q->fid, q->pattern,
                                     irp_waiter_cb, q->w);
}

typedef struct { RDPPeerContext *ctx; uint32_t devId; uint32_t fid; IrpWaiter *w; } DeleteArgs;
static bool send_delete(void *a) {
    DeleteArgs *d = (DeleteArgs *)a;
    return rdpdr_send_delete_req(d->ctx, d->devId, d->fid, irp_waiter_cb, d->w);
}

typedef struct { RDPPeerContext *ctx; uint32_t devId; uint32_t fid; const char *newPath;
                 bool replace; IrpWaiter *w; } RenameArgs;
static bool send_rename(void *a) {
    RenameArgs *r = (RenameArgs *)a;
    return rdpdr_send_rename_req(r->ctx, r->devId, r->fid, r->newPath, r->replace,
                                 irp_waiter_cb, r->w);
}

/*
 * irp_send_wait — take xportLock, call sendFn(args) with the waiter already
 * embedded in args by the caller, release lock, then block until completion.
 *
 * On success: returns the waiter (caller must call irp_waiter_unref when done).
 * On send failure or timeout: cleans up and returns NULL.
 *
 * w_alloc is the IrpWaiter that was just allocated and placed in args; on
 * send failure (IRP never registered) we need to free both of its refs.
 */
static IrpWaiter *irp_send_wait(RDPPeerContext *ctx,
                                  bool (*sendFn)(void *), void *args,
                                  IrpWaiter *w_alloc) {
    pthread_mutex_lock(&ctx->xportLock);
    bool ok = sendFn(args);
    pthread_mutex_unlock(&ctx->xportLock);

    if (!ok) {
        /* Two possible failure modes:
         *   A) rdpdr_alloc_request returned 0 (table full) — no slot was taken,
         *      the callback ref was never handed to a pending slot, so we own
         *      both refs and must free both.
         *   B) stream-alloc or write failed AFTER alloc — rdpdr_free_request was
         *      called inside the helper and fired the callback (dropping its ref).
         *      w_alloc->done == true.
         * Peek at `done` (under lock) to distinguish. */
        pthread_mutex_lock(&w_alloc->mu);
        bool cb_fired = w_alloc->done;
        pthread_mutex_unlock(&w_alloc->mu);

        if (!cb_fired) {
            /* Case A: drop the phantom callback ref, then our own. */
            irp_waiter_unref(w_alloc); /* drops callback ref (from 2→1) */
        }
        irp_waiter_unref(w_alloc); /* drops our ref (from 1→0, frees) */
        return NULL;
    }

    if (!irp_waiter_wait(w_alloc)) {
        rdp_verbose("webdav: IRP timed out after %d seconds", IRP_TIMEOUT_SEC);
        /* irp_waiter_wait already dropped the caller's reference on timeout. */
        return NULL;
    }
    return w_alloc;  /* caller owns reference; must call irp_waiter_unref() */
}

/* Opens a path on the client drive. Returns the NTSTATUS (0: opened, the
 * FileId in *fileId_out, the CREATE Information byte in *info_out) or
 * WEBDAV_NO_REPLY. */
static uint32_t open_file(RDPPeerContext *ctx, uint32_t devId, const char *path,
                          uint32_t access, uint32_t disposition, uint32_t options,
                          uint32_t *fileId_out, uint8_t *info_out) {
    IrpWaiter *w = irp_waiter_alloc();
    if (!w) return WEBDAV_NO_REPLY;
    CreateArgs args = { ctx, devId, path, access, disposition, options, w };
    IrpWaiter *ret = irp_send_wait(ctx, send_create, &args, w);
    if (!ret) return WEBDAV_NO_REPLY;
    uint32_t st = ret->ioStatus;
    if (st == 0 && ret->payload && ret->payloadLen >= 4) {
        *fileId_out = rd32(ret->payload);         /* DR_CREATE_RSP: FileId(4), Information(1) */
        if (info_out) *info_out = ret->payloadLen >= 5 ? ret->payload[4] : 0;
    } else {
        if (st == 0) st = NT_UNSUCCESSFUL;        /* success without a FileId */
        rdp_verbose("webdav: open \"%s\" failed: 0x%08x", path, st);
    }
    irp_waiter_unref(ret);
    return st;
}

static bool close_file(RDPPeerContext *ctx, uint32_t devId, uint32_t fid) {
    IrpWaiter *w = irp_waiter_alloc();
    if (!w) return false;
    CloseArgs args = { ctx, devId, fid, w };
    IrpWaiter *ret = irp_send_wait(ctx, send_close, &args, w);
    if (!ret) return false;
    irp_waiter_unref(ret);
    return true;
}

/* ── Client-drive operations ────────────────────────────────────────────── */

static RDPPeerContext *srv_ctx(RDPWebDAVServer *srv) {
    return (RDPPeerContext *)srv->peer->context;
}

/* Sends one IRP through fn and returns its status (WEBDAV_NO_REPLY if none). */
static uint32_t irp_status(RDPPeerContext *ctx, bool (*fn)(void *), void *args, IrpWaiter *w) {
    IrpWaiter *r = irp_send_wait(ctx, fn, args, w);
    if (!r) return WEBDAV_NO_REPLY;
    uint32_t st = r->ioStatus;
    irp_waiter_unref(r);
    return st;
}

/* Lists the entries matching pattern ("\dir\*", or an exact "\dir\name")
 * through the open directory fid. The client answers one entry per IRP, so
 * this asks again (InitialQuery 0) until it reports no more files, answers
 * empty, or the visitor stops. Returns the first answer's status: 0 when
 * something matched. */
static uint32_t query_dir(RDPPeerContext *ctx, uint32_t devId, uint32_t fid,
                          const char *pattern, DirVisitor visit, void *ud) {
    uint32_t first = WEBDAV_NO_REPLY;
    for (uint32_t i = 0; i < WEBDAV_MAX_ENTRIES; i++) {
        IrpWaiter *w = irp_waiter_alloc();
        if (!w) break;
        QueryDirArgs q = { ctx, devId, fid, i == 0 ? pattern : NULL, w };
        IrpWaiter *r = irp_send_wait(ctx, send_query_dir, &q, w);
        if (!r) break;
        uint32_t st = r->ioStatus;
        int seen = 0;
        if (st == 0 && r->payload && r->payloadLen >= 4) {
            /* DR_DRIVE_QUERY_DIRECTORY_RSP: Length(4), then Length bytes. */
            uint32_t blen = rd32(r->payload);
            if (blen > r->payloadLen - 4) blen = r->payloadLen - 4;
            seen = parse_ffdi(r->payload + 4, blen, visit, ud);
        }
        irp_waiter_unref(r);
        if (i == 0) first = st;
        if (st != 0 || seen <= 0) break;
    }
    return first;
}

typedef struct { const char *want; DirEntry *out; bool found; } StatFind;
static bool stat_visit(const DirEntry *e, void *ud) {
    StatFind *f = (StatFind *)ud;
    if (strcasecmp(e->name, f->want) != 0) return true;
    *f->out = *e;
    f->found = true;
    return false;
}

/* Looks up one drive path (rdpdr form). The root is a directory dated now;
 * anything else is found by an exact-name query on its parent, which also
 * gives its size and time. Returns 0, or the status that stopped it. */
static uint32_t stat_path(RDPPeerContext *ctx, uint32_t devId, const char *rdpPath,
                          DirEntry *out) {
    memset(out, 0, sizeof(*out));
    if (rdpPath[0] == '\0') {
        out->attrs = FILE_ATTR_DIRECTORY;
        out->lastWrite = (uint64_t)time(NULL) * 10000000ULL + 116444736000000000ULL;
        return 0;
    }
    const char *slash = strrchr(rdpPath, '\\');     /* rdpPath starts with one */
    char parent[WEBDAV_MAX_PATH];
    size_t plen = (size_t)(slash - rdpPath);
    memcpy(parent, rdpPath, plen);
    parent[plen] = '\0';                              /* "" for a top-level name */
    uint32_t fid = 0;
    uint32_t st = open_file(ctx, devId, parent, WD_LIST_DIRECTORY | WD_SYNCHRONIZE,
                            WD_FILE_OPEN, WD_OPT_DIRECTORY | WD_OPT_SYNC_IO, &fid, NULL);
    if (st) return st;
    StatFind f = { slash + 1, out, false };
    uint32_t qst = query_dir(ctx, devId, fid, rdpPath, stat_visit, &f);
    close_file(ctx, devId, fid);
    if (f.found) return 0;
    return (qst == 0 || qst == NT_NO_MORE_FILES) ? NT_NO_SUCH_FILE : qst;
}

/* Writes len bytes at off, resending the rest after a short write. */
static uint32_t write_at(RDPPeerContext *ctx, uint32_t devId, uint32_t fid,
                         uint64_t off, const uint8_t *data, size_t len) {
    size_t done = 0;
    while (done < len) {
        IrpWaiter *w = irp_waiter_alloc();
        if (!w) return WEBDAV_NO_REPLY;
        WriteArgs a = { ctx, devId, fid, off + done, data + done, (uint32_t)(len - done), w };
        IrpWaiter *r = irp_send_wait(ctx, send_write, &a, w);
        if (!r) return WEBDAV_NO_REPLY;
        uint32_t st = r->ioStatus;
        /* DR_WRITE_RSP: Length(4) = bytes written, Padding(1). */
        uint32_t n = (st == 0 && r->payload && r->payloadLen >= 4) ? rd32(r->payload) : 0;
        irp_waiter_unref(r);
        if (st) return st;
        if (n == 0) return NT_UNSUCCESSFUL;
        done += n < len - done ? n : len - done;
    }
    return 0;
}

/* ── HTTP request ───────────────────────────────────────────────────────── */

typedef struct {
    char      method[16];
    char      path[WEBDAV_MAX_PATH];         /* percent-decoded */
    char      destination[WEBDAV_MAX_PATH];  /* MOVE: decoded path of Destination */
    char      lockToken[128];                /* from an If: header, without <> */
    int       depth;                         /* 0, 1, or 99 = infinity */
    long long contentLength;                 /* -1 = none */
    bool      chunked, expectContinue, overwrite, hasDestination;
    bool      authPresent, authorized;       /* Authorization: sent / right */
    char      range[64], ifRange[96];        /* Range:, If-Range: (empty = not sent) */
} HttpRequest;

static const char *reason_for(int code) {
    switch (code) {
    case 200: return "OK";                case 201: return "Created";
    case 204: return "No Content";        case 207: return "Multi-Status";
    case 206: return "Partial Content";   case 416: return "Range Not Satisfiable";
    case 400: return "Bad Request";       case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";         case 405: return "Method Not Allowed";
    case 409: return "Conflict";          case 411: return "Length Required";
    case 412: return "Precondition Failed"; case 413: return "Payload Too Large";
    case 414: return "URI Too Long";      case 423: return "Locked";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error"; case 501: return "Not Implemented";
    case 502: return "Bad Gateway";       case 507: return "Insufficient Storage";
    default:  return "Error";
    }
}

static void respond_code(int fd, int code) {
    http_respond(fd, code, reason_for(code), NULL, NULL, 0);
}

static int http_code_for(uint32_t st) {
    switch (st) {
    case 0: return 200;
    case WEBDAV_NO_REPLY: return 502;
    case NT_NO_SUCH_FILE: case NT_OBJECT_NAME_NOT_FOUND:
    case NT_OBJECT_PATH_NOT_FOUND: case NT_NO_MORE_FILES: return 404;
    case NT_ACCESS_DENIED: case NT_MEDIA_WRITE_PROTECTED:
    case NT_CANNOT_DELETE: case NT_OBJECT_NAME_INVALID: return 403;
    case NT_OBJECT_NAME_COLLISION: return 412;
    case NT_SHARING_VIOLATION: case NT_DELETE_PENDING: return 423;
    case NT_DISK_FULL: return 507;
    case NT_FILE_IS_A_DIRECTORY: case NT_NOT_A_DIRECTORY:
    case NT_DIRECTORY_NOT_EMPTY: return 409;
    default: return 500;
    }
}

/* Answers a failed drive operation and logs it (not-found only in verbose). */
static void respond_failure(int fd, const char *method, const char *path, uint32_t st) {
    int code = http_code_for(st);
    if (code == 404)
        rdp_verbose("webdav: %s %s: not found (0x%08x)", method, path, st);
    else if (st == WEBDAV_NO_REPLY)
        rdp_info("webdav: %s %s: no answer from the client within %d s", method, path,
                 IRP_TIMEOUT_SEC);
    else
        rdp_info("webdav: %s %s: client status 0x%08x, HTTP %d", method, path, st, code);
    respond_code(fd, code);
}

/* Byte index just past the blank line that ends the headers, or 0. */
static size_t header_end(const char *buf, size_t len) {
    for (size_t i = 0; i + 1 < len; i++) {
        if (buf[i] != '\n') continue;
        if (buf[i + 1] == '\n') return i + 2;
        if (i + 2 < len && buf[i + 1] == '\r' && buf[i + 2] == '\n') return i + 3;
    }
    return 0;
}

/* A request target or Destination value as a decoded URL path (query
 * dropped, scheme and host removed). Returns 0 or the HTTP status to answer. */
static int target_to_path(const char *v, size_t vlen, char *out, size_t outCap) {
    char raw[WEBDAV_MAX_PATH];
    if (vlen >= sizeof(raw)) return 414;
    memcpy(raw, v, vlen);
    raw[vlen] = '\0';
    char *q = strchr(raw, '?');
    if (q) *q = '\0';
    const char *p = rdp_url_path_part(raw);
    if (strlen(p) + 1 >= outCap) return 414;
    snprintf(out, outCap, "%s", *p ? p : "/");
    return rdp_url_decode(out) ? 0 : 400;
}

/* True if line (len bytes, no LF) is header `name`; *val/*vlen get its
 * trimmed value. */
static bool hdr_is(const char *line, size_t len, const char *name,
                   const char **val, size_t *vlen) {
    size_t n = strlen(name);
    if (len <= n || strncasecmp(line, name, n) != 0 || line[n] != ':') return false;
    const char *v = line + n + 1, *end = line + len;
    while (v < end && (*v == ' ' || *v == '\t')) v++;
    while (end > v && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r')) end--;
    *val = v;
    *vlen = (size_t)(end - v);
    return true;
}

/* Parses the request line and the headers this server uses; buf[0..len) is
 * the header block, and Authorization is checked against expectUserPass.
 * Returns 0 or the HTTP status to answer. */
static int parse_request(const char *buf, size_t len, const char *expectUserPass,
                         HttpRequest *req) {
    memset(req, 0, sizeof(*req));
    req->depth = 1;
    req->contentLength = -1;
    req->overwrite = true;

    const char *end = (const char *)memchr(buf, '\n', len);
    if (!end) return 400;
    const char *sp1 = (const char *)memchr(buf, ' ', (size_t)(end - buf));
    if (!sp1 || sp1 == buf || (size_t)(sp1 - buf) >= sizeof(req->method)) return 400;
    memcpy(req->method, buf, (size_t)(sp1 - buf));
    const char *t = sp1 + 1;
    const char *sp2 = (const char *)memchr(t, ' ', (size_t)(end - t));
    if (!sp2) return 400;
    int st = target_to_path(t, (size_t)(sp2 - t), req->path, sizeof(req->path));
    if (st) return st;

    for (const char *p = end + 1; p < buf + len; ) {
        const char *nl = (const char *)memchr(p, '\n', (size_t)(buf + len - p));
        size_t l = nl ? (size_t)(nl - p) : (size_t)(buf + len - p);
        const char *v;
        size_t vl;
        if (hdr_is(p, l, "Depth", &v, &vl)) {
            req->depth = (vl == 1 && v[0] == '0') ? 0 : (vl == 1 && v[0] == '1') ? 1 : 99;
        } else if (hdr_is(p, l, "Content-Length", &v, &vl)) {
            char num[24];
            if (vl == 0 || vl >= sizeof(num)) return 400;
            memcpy(num, v, vl);
            num[vl] = '\0';
            char *e;
            long long n = strtoll(num, &e, 10);
            if (*e || n < 0) return 400;
            req->contentLength = n;
        } else if (hdr_is(p, l, "Transfer-Encoding", &v, &vl)) {
            if (vl >= 7 && strncasecmp(v + vl - 7, "chunked", 7) == 0) req->chunked = true;
            else return 501;
        } else if (hdr_is(p, l, "Expect", &v, &vl)) {
            if (vl == 12 && strncasecmp(v, "100-continue", 12) == 0) req->expectContinue = true;
        } else if (hdr_is(p, l, "Overwrite", &v, &vl)) {
            req->overwrite = !(vl == 1 && (v[0] == 'F' || v[0] == 'f'));
        } else if (hdr_is(p, l, "Destination", &v, &vl)) {
            st = target_to_path(v, vl, req->destination, sizeof(req->destination));
            if (st) return st;
            req->hasDestination = true;
        } else if (hdr_is(p, l, "Range", &v, &vl)) {
            if (vl < sizeof(req->range)) { memcpy(req->range, v, vl); req->range[vl] = '\0'; }
        } else if (hdr_is(p, l, "If-Range", &v, &vl)) {
            if (vl < sizeof(req->ifRange)) { memcpy(req->ifRange, v, vl); req->ifRange[vl] = '\0'; }
        } else if (hdr_is(p, l, "Authorization", &v, &vl)) {
            req->authPresent = true;
            req->authorized = rdp_http_basic_auth_ok(v, vl, expectUserPass);
        } else if (hdr_is(p, l, "If", &v, &vl)) {
            char tmp[256];
            size_t tl = vl < sizeof(tmp) - 1 ? vl : sizeof(tmp) - 1;
            memcpy(tmp, v, tl);
            tmp[tl] = '\0';
            char *b = strstr(tmp, "<opaquelocktoken:");
            char *e = b ? strchr(b, '>') : NULL;
            size_t tokLen = (b && e) ? (size_t)(e - b - 1) : 0;
            bool clean = tokLen > 0 && tokLen < sizeof(req->lockToken);
            for (size_t i = 0; clean && i < tokLen; i++) {
                char c = b[1 + i];
                clean = isalnum((unsigned char)c) || c == ':' || c == '-';
            }
            if (clean) {
                memcpy(req->lockToken, b + 1, tokLen);
                req->lockToken[tokLen] = '\0';
            }
        }
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

/* ── Request body (Content-Length or chunked; Finder sends chunked PUTs) ── */

typedef struct {
    int            fd;
    const uint8_t *pre;          /* body bytes read along with the headers */
    size_t         preLen, prePos;
    long long      left;         /* identity body: bytes still to read */
    bool           chunked;
    uint64_t       chunkLeft;    /* chunked: bytes left in the current chunk */
    bool           done, failed;
} BodyReader;

static ssize_t raw_read(BodyReader *b, uint8_t *dst, size_t cap) {
    if (b->prePos < b->preLen) {
        size_t n = b->preLen - b->prePos;
        if (n > cap) n = cap;
        memcpy(dst, b->pre + b->prePos, n);
        b->prePos += n;
        return (ssize_t)n;
    }
    for (;;) {
        ssize_t n = read(b->fd, dst, cap);
        if (n < 0 && errno == EINTR) continue;
        return n;    /* 0 = closed; -1 = error or the receive timeout */
    }
}

/* One line without its CRLF; false if the stream ends or the line is too long. */
static bool raw_line(BodyReader *b, char *line, size_t cap) {
    size_t n = 0;
    for (;;) {
        uint8_t c;
        if (raw_read(b, &c, 1) != 1) return false;
        if (c == '\n') break;
        if (n + 1 >= cap) return false;
        line[n++] = (char)c;
    }
    if (n > 0 && line[n - 1] == '\r') n--;
    line[n] = '\0';
    return true;
}

/* Up to cap body bytes; 0 at the end of the body, -1 if it broke off. */
static ssize_t body_read(BodyReader *b, uint8_t *dst, size_t cap) {
    if (b->failed) return -1;
    if (b->done || cap == 0) return 0;
    if (!b->chunked) {
        if (b->left <= 0) { b->done = true; return 0; }
        if ((long long)cap > b->left) cap = (size_t)b->left;
        ssize_t n = raw_read(b, dst, cap);
        if (n <= 0) { b->failed = true; return -1; }
        b->left -= n;
        if (b->left == 0) b->done = true;
        return n;
    }
    if (b->chunkLeft == 0) {
        char line[128];
        if (!raw_line(b, line, sizeof(line))) { b->failed = true; return -1; }
        char *e;
        unsigned long long sz = strtoull(line, &e, 16);
        if (e == line || (*e && *e != ';' && *e != ' ' && *e != '\t')) {
            b->failed = true;
            return -1;
        }
        if (sz == 0) {          /* last chunk: skip trailers up to the blank line */
            do {
                if (!raw_line(b, line, sizeof(line))) { b->failed = true; return -1; }
            } while (line[0]);
            b->done = true;
            return 0;
        }
        b->chunkLeft = sz;
    }
    if (cap > b->chunkLeft) cap = (size_t)b->chunkLeft;
    ssize_t n = raw_read(b, dst, cap);
    if (n <= 0) { b->failed = true; return -1; }
    b->chunkLeft -= (uint64_t)n;
    if (b->chunkLeft == 0) {
        char crlf[4];
        if (!raw_line(b, crlf, sizeof(crlf)) || crlf[0]) { b->failed = true; return -1; }
    }
    return n;
}

/* Reads and drops the body; false if it is broken or longer than max. */
static bool body_drain(BodyReader *b, size_t max) {
    uint8_t sink[4096];
    size_t total = 0;
    for (;;) {
        ssize_t n = body_read(b, sink, sizeof(sink));
        if (n < 0) return false;
        if (n == 0) return true;
        total += (size_t)n;
        if (total > max) return false;
    }
}

/* ── Request handlers ───────────────────────────────────────────────────── */

static void handle_options(int fd) {
    http_respond(fd, 200, "OK",
                 "Allow: OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL, MOVE, LOCK, UNLOCK\r\n",
                 NULL, 0);
}

typedef struct {
    XmlBuf     *x;
    const char *dirUrl;      /* decoded URL path of the listed directory */
    uint32_t    count;
} ListCtx;

static bool list_visit(const DirEntry *e, void *ud) {
    ListCtx *l = (ListCtx *)ud;
    if (strcmp(e->name, ".") == 0 || strcmp(e->name, "..") == 0) return true;
    if (strchr(e->name, '/')) return true;                   /* not addressable */
    /* Protected OS files ($RECYCLE.BIN, pagefile.sys), hidden in Explorer too. */
    if ((e->attrs & (FILE_ATTR_HIDDEN | FILE_ATTR_SYSTEM)) == (FILE_ATTR_HIDDEN | FILE_ATTR_SYSTEM))
        return true;
    char url[WEBDAV_MAX_PATH];
    size_t dl = strlen(l->dirUrl);
    int n = snprintf(url, sizeof(url), "%s%s%s", l->dirUrl,
                     (dl > 0 && l->dirUrl[dl - 1] == '/') ? "" : "/", e->name);
    if (n < 0 || (size_t)n >= sizeof(url)) return true;
    propfind_append(l->x, url, (e->attrs & FILE_ATTR_DIRECTORY) != 0, e->name,
                    e->size, e->lastWrite);
    l->count++;
    return true;
}

/* PROPFIND — the entry itself, plus its children for Depth 1 on a directory. */
static void handle_propfind(RDPWebDAVServer *srv, int fd, const HttpRequest *req) {
    RDPPeerContext *ctx = srv_ctx(srv);
    const uint32_t devId = srv->deviceId;
    char rdpPath[WEBDAV_MAX_PATH];
    if (!rdpdr_path_from_url(req->path, rdpPath, sizeof(rdpPath))) { respond_code(fd, 403); return; }

    DirEntry self;
    uint32_t st = stat_path(ctx, devId, rdpPath, &self);
    if (st) { respond_failure(fd, req->method, req->path, st); return; }
    bool isDir = (self.attrs & FILE_ATTR_DIRECTORY) != 0;

    XmlBuf x = { 0 };
    xb_printf(&x, "<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\">");
    propfind_append(&x, req->path, isDir, rdpPath[0] ? self.name : srv->driveName,
                    self.size, self.lastWrite);

    if (isDir && req->depth >= 1) {
        uint32_t fid = 0;
        st = open_file(ctx, devId, rdpPath, WD_LIST_DIRECTORY | WD_SYNCHRONIZE, WD_FILE_OPEN,
                       WD_OPT_DIRECTORY | WD_OPT_SYNC_IO, &fid, NULL);
        if (st) { free(x.buf); respond_failure(fd, req->method, req->path, st); return; }
        char pattern[WEBDAV_MAX_PATH + 3];
        snprintf(pattern, sizeof(pattern), "%s\\*", rdpPath);
        ListCtx lc = { &x, req->path, 0 };
        uint32_t qst = query_dir(ctx, devId, fid, pattern, list_visit, &lc);
        close_file(ctx, devId, fid);
        if (qst != 0 && qst != NT_NO_MORE_FILES && qst != NT_NO_SUCH_FILE) {
            free(x.buf);
            respond_failure(fd, req->method, req->path, qst);
            return;
        }
        if (!srv->loggedList) {
            srv->loggedList = true;
            rdp_info("webdav: drive \"%s\": first listing OK (%s, %u entries)",
                     srv->driveName, rdpPath[0] ? "a folder" : "the root", lc.count);
        }
    }
    xb_printf(&x, "</D:multistatus>");
    if (x.oom) { free(x.buf); respond_code(fd, 500); return; }
    http_respond(fd, 207, "Multi-Status", "Content-Type: application/xml; charset=\"utf-8\"\r\n",
                 x.buf, x.len);
    free(x.buf);
}

/* Answers 416 for a range that starts at or after the end of the file. */
static void respond_range_not_satisfiable(int fd, uint64_t size) {
    char cr[64];
    snprintf(cr, sizeof(cr), "Content-Range: bytes */%llu\r\n", (unsigned long long)size);
    http_respond(fd, 416, reason_for(416), cr, NULL, 0);
}

/* GET / HEAD — a file's bytes. The whole file is streamed chunked as the client reads it.
 * A single Range gets 206 with exactly those bytes: macOS's webdavfs asks for part of a big
 * file when a page of it is needed, and puts whatever comes back at that offset, so the
 * whole file sent instead landed in the wrong place. */
static void handle_get(RDPWebDAVServer *srv, int fd, const HttpRequest *req, bool headOnly) {
    RDPPeerContext *ctx = srv_ctx(srv);
    const uint32_t devId = srv->deviceId;
    char rdpPath[WEBDAV_MAX_PATH];
    if (!rdpdr_path_from_url(req->path, rdpPath, sizeof(rdpPath))) { respond_code(fd, 403); return; }
    DirEntry e;
    uint32_t st = stat_path(ctx, devId, rdpPath, &e);
    if (st) { respond_failure(fd, req->method, req->path, st); return; }
    if (e.attrs & FILE_ATTR_DIRECTORY) { respond_code(fd, 405); return; }

    char date[40], etag[40], hdrs[512];
    rdp_http_date_from_filetime(e.lastWrite, date, sizeof(date));
    snprintf(etag, sizeof(etag), "\"%llx-%llx\"", (unsigned long long)e.lastWrite,
             (unsigned long long)e.size);

    uint64_t first = 0, last = 0;
    bool ranged = false;
    if (!headOnly && req->range[0] &&
        /* If-Range: a part only of the same file the client already saw, else all of it. */
        (!req->ifRange[0] || strcmp(req->ifRange, etag) == 0 || strcmp(req->ifRange, date) == 0)) {
        int rr = rdp_http_byte_range(req->range, strlen(req->range), e.size, &first, &last);
        if (rr < 0) { respond_range_not_satisfiable(fd, e.size); return; }
        ranged = rr > 0;
    }

    int hn = snprintf(hdrs, sizeof(hdrs),
                      "Content-Type: application/octet-stream\r\nAccept-Ranges: bytes\r\n"
                      "Last-Modified: %s\r\nETag: %s\r\n", date, etag);
    if (ranged)
        snprintf(hdrs + hn, sizeof(hdrs) - (size_t)hn, "Content-Range: bytes %llu-%llu/%llu\r\n",
                 (unsigned long long)first, (unsigned long long)last, (unsigned long long)e.size);
    else if (!headOnly)
        snprintf(hdrs + hn, sizeof(hdrs) - (size_t)hn, "Transfer-Encoding: chunked\r\n");
    if (headOnly) { http_head(fd, 200, "OK", hdrs, (long long)e.size); return; }

    uint32_t fid = 0;
    st = open_file(ctx, devId, rdpPath, WD_FILE_GENERIC_READ, WD_FILE_OPEN,
                   WD_OPT_NON_DIRECTORY | WD_OPT_SYNC_IO, &fid, NULL);
    if (st) { respond_failure(fd, req->method, req->path, st); return; }

    /* The status line goes out only once the first read has succeeded, so a refused read
     * (access denied, a lock conflict) is a clean HTTP error. A body cut off after the
     * status line makes webdavfs drop the whole mount. */
    bool ok = true, started = false;
    uint64_t off = first;
    uint64_t left = ranged ? last - first + 1 : UINT64_MAX;   /* chunked: to the end of file */
    while (ok && left > 0) {
        IrpWaiter *w = irp_waiter_alloc();
        if (!w) { st = WEBDAV_NO_REPLY; ok = false; break; }
        uint32_t want = left < WEBDAV_IO_CHUNK ? (uint32_t)left : WEBDAV_IO_CHUNK;
        ReadArgs ra = { ctx, devId, fid, off, want, w };
        IrpWaiter *r = irp_send_wait(ctx, send_read, &ra, w);
        if (!r) { st = WEBDAV_NO_REPLY; ok = false; break; }
        st = r->ioStatus;
        uint32_t n = 0;
        if (st == 0 && r->payload && r->payloadLen >= 4) {
            n = rd32(r->payload);                 /* DR_READ_RSP: Length(4), ReadData */
            if (n > r->payloadLen - 4) n = r->payloadLen - 4;
            if (n > want) n = want;               /* never more than asked for */
        }
        if (st == NT_END_OF_FILE) st = 0;         /* carries no data */
        if (st == 0 && n == 0 && ranged && !started) {   /* the file shrank past the range */
            irp_waiter_unref(r);
            close_file(ctx, devId, fid);
            respond_range_not_satisfiable(fd, e.size);
            return;
        }
        if (st == 0 && !started) {
            started = true;
            ok = ranged ? http_head(fd, 206, "Partial Content", hdrs, (long long)left)
                        : http_head(fd, 200, "OK", hdrs, -1);
        }
        if (ok && n > 0) {
            if (ranged) {
                ok = http_send(fd, (const char *)r->payload + 4, n);
                left -= n;
            } else {
                char ch[16];
                int hl = snprintf(ch, sizeof(ch), "%x\r\n", (unsigned)n);
                ok = http_send(fd, ch, (size_t)hl) &&
                     http_send(fd, (const char *)r->payload + 4, n) &&
                     http_send(fd, "\r\n", 2);
            }
            off += n;
        }
        irp_waiter_unref(r);
        if (st != 0) { ok = false; break; }
        if (n < want) break;                      /* short read: end of file */
    }
    close_file(ctx, devId, fid);
    if (!started) { respond_failure(fd, req->method, req->path, st); return; }
    if (ok && (ranged ? left == 0 : http_send(fd, "0\r\n\r\n", 5))) {
        if (!srv->loggedRead) {
            srv->loggedRead = true;
            rdp_info("webdav: drive \"%s\": first file read OK (%llu bytes)", srv->driveName,
                     (unsigned long long)(off - first));
        }
    } else if (st) {
        /* No final chunk, or a body short of its Content-Length: the client sees a cut-off
         * body, not a short file. */
        rdp_info("webdav: GET %s stopped after %llu bytes: client status 0x%08x",
                 req->path, (unsigned long long)(off - first), st);
    }
}

/* PUT — create or replace a file with the request body. */
static void handle_put(RDPWebDAVServer *srv, int fd, const HttpRequest *req, BodyReader *body) {
    RDPPeerContext *ctx = srv_ctx(srv);
    const uint32_t devId = srv->deviceId;
    char rdpPath[WEBDAV_MAX_PATH];
    if (!rdpdr_path_from_url(req->path, rdpPath, sizeof(rdpPath)) || !rdpPath[0]) {
        respond_code(fd, 403);
        return;
    }
    if (!req->chunked && req->contentLength < 0) { respond_code(fd, 411); return; }

    uint32_t fid = 0;
    uint8_t info = 0;
    uint32_t st = open_file(ctx, devId, rdpPath,
                            WD_FILE_GENERIC_READ | WD_FILE_GENERIC_WRITE,
                            WD_FILE_OVERWRITE_IF, WD_OPT_NON_DIRECTORY | WD_OPT_SYNC_IO,
                            &fid, &info);
    if (st) { respond_failure(fd, req->method, req->path, st); return; }
    if (req->expectContinue) http_send(fd, "HTTP/1.1 100 Continue\r\n\r\n", 25);

    uint8_t *chunk = (uint8_t *)malloc(WEBDAV_IO_CHUNK);
    bool haveBuf = chunk != NULL, bodyOk = haveBuf;
    uint64_t off = 0;
    while (bodyOk && st == 0) {
        size_t have = 0;
        while (have < WEBDAV_IO_CHUNK) {
            ssize_t n = body_read(body, chunk + have, WEBDAV_IO_CHUNK - have);
            if (n < 0) { bodyOk = false; break; }
            if (n == 0) break;
            have += (size_t)n;
        }
        if (!bodyOk || have == 0) break;
        st = write_at(ctx, devId, fid, off, chunk, have);
        if (st == 0) off += have;
        if (body->done) break;
    }
    close_file(ctx, devId, fid);
    free(chunk);
    if (!bodyOk) {
        rdp_info("webdav: PUT %s: %s after %llu bytes", req->path,
                 haveBuf ? "the request body broke off" : "out of memory",
                 (unsigned long long)off);
        respond_code(fd, haveBuf ? 400 : 500);
        return;
    }
    if (st) { respond_failure(fd, req->method, req->path, st); return; }
    if (!srv->loggedWrite) {
        srv->loggedWrite = true;
        rdp_info("webdav: drive \"%s\": first file write OK (%llu bytes)", srv->driveName,
                 (unsigned long long)off);
    }
    respond_code(fd, info == WD_FILE_CREATED ? 201 : 204);
}

/* DELETE — a file, or an empty directory (the Finder empties it first). */
static void handle_delete(RDPWebDAVServer *srv, int fd, const HttpRequest *req) {
    RDPPeerContext *ctx = srv_ctx(srv);
    const uint32_t devId = srv->deviceId;
    char rdpPath[WEBDAV_MAX_PATH];
    if (!rdpdr_path_from_url(req->path, rdpPath, sizeof(rdpPath)) || !rdpPath[0]) {
        respond_code(fd, 403);
        return;
    }
    DirEntry e;
    uint32_t st = stat_path(ctx, devId, rdpPath, &e);
    if (st) { respond_failure(fd, req->method, req->path, st); return; }
    bool isDir = (e.attrs & FILE_ATTR_DIRECTORY) != 0;
    uint32_t fid = 0;
    st = open_file(ctx, devId, rdpPath, WD_DELETE | WD_SYNCHRONIZE, WD_FILE_OPEN,
                   (isDir ? WD_OPT_DIRECTORY : WD_OPT_NON_DIRECTORY) |
                   WD_OPT_DELETE_ON_CLOSE | WD_OPT_SYNC_IO, &fid, NULL);
    if (st) { respond_failure(fd, req->method, req->path, st); return; }
    IrpWaiter *w = irp_waiter_alloc();
    if (w) {
        DeleteArgs d = { ctx, devId, fid, w };
        st = irp_status(ctx, send_delete, &d, w);
    } else {
        st = WEBDAV_NO_REPLY;
    }
    close_file(ctx, devId, fid);
    if (st) { respond_failure(fd, req->method, req->path, st); return; }
    respond_code(fd, 204);
}

/* MKCOL — create a directory. */
static void handle_mkcol(RDPWebDAVServer *srv, int fd, const HttpRequest *req) {
    RDPPeerContext *ctx = srv_ctx(srv);
    const uint32_t devId = srv->deviceId;
    char rdpPath[WEBDAV_MAX_PATH];
    if (!rdpdr_path_from_url(req->path, rdpPath, sizeof(rdpPath))) { respond_code(fd, 403); return; }
    if (!rdpPath[0]) { respond_code(fd, 405); return; }
    uint32_t fid = 0;
    uint32_t st = open_file(ctx, devId, rdpPath, WD_LIST_DIRECTORY | WD_SYNCHRONIZE,
                            WD_FILE_CREATE, WD_OPT_DIRECTORY | WD_OPT_SYNC_IO, &fid, NULL);
    if (st == NT_OBJECT_NAME_COLLISION) { respond_code(fd, 405); return; }
    if (st == NT_OBJECT_PATH_NOT_FOUND) { respond_code(fd, 409); return; }
    if (st) { respond_failure(fd, req->method, req->path, st); return; }
    close_file(ctx, devId, fid);
    respond_code(fd, 201);
}

/* MOVE — rename or move (Finder renames; apps save by renaming a temp file). */
static void handle_move(RDPWebDAVServer *srv, int fd, const HttpRequest *req) {
    RDPPeerContext *ctx = srv_ctx(srv);
    const uint32_t devId = srv->deviceId;
    char src[WEBDAV_MAX_PATH], dst[WEBDAV_MAX_PATH];
    if (!req->hasDestination) { respond_code(fd, 400); return; }
    if (!rdpdr_path_from_url(req->path, src, sizeof(src)) || !src[0] ||
        !rdpdr_path_from_url(req->destination, dst, sizeof(dst)) || !dst[0] ||
        strcmp(src, dst) == 0) {
        respond_code(fd, 403);
        return;
    }
    DirEntry e;
    uint32_t st = stat_path(ctx, devId, src, &e);
    if (st) { respond_failure(fd, req->method, req->path, st); return; }
    bool isDir = (e.attrs & FILE_ATTR_DIRECTORY) != 0;
    uint32_t fid = 0;
    st = open_file(ctx, devId, src, WD_DELETE | WD_SYNCHRONIZE, WD_FILE_OPEN,
                   (isDir ? WD_OPT_DIRECTORY : WD_OPT_NON_DIRECTORY) | WD_OPT_SYNC_IO,
                   &fid, NULL);
    if (st) { respond_failure(fd, req->method, req->path, st); return; }
    IrpWaiter *w = irp_waiter_alloc();
    if (w) {
        RenameArgs ra = { ctx, devId, fid, dst, req->overwrite, w };
        st = irp_status(ctx, send_rename, &ra, w);
    } else {
        st = WEBDAV_NO_REPLY;
    }
    close_file(ctx, devId, fid);
    if (st) { respond_failure(fd, req->method, req->path, st); return; }
    respond_code(fd, 201);
}

/* LOCK — the Finder mounts read-only unless the server offers DAV class 2,
 * so locks are granted (one local user; nothing to arbitrate). Locking a
 * missing file creates it empty (RFC 4918 9.10.4); a LOCK with no body and
 * an If: token is a refresh. */
static void handle_lock(RDPWebDAVServer *srv, int fd, const HttpRequest *req, bool hasBody) {
    RDPPeerContext *ctx = srv_ctx(srv);
    const uint32_t devId = srv->deviceId;
    char rdpPath[WEBDAV_MAX_PATH];
    if (!rdpdr_path_from_url(req->path, rdpPath, sizeof(rdpPath))) { respond_code(fd, 403); return; }
    char token[160];
    int code = 200;
    if (!hasBody && req->lockToken[0]) {
        snprintf(token, sizeof(token), "%s", req->lockToken);
    } else {
        snprintf(token, sizeof(token), "opaquelocktoken:%08x-%04x-4%03x-%04x-%08x%04x",
                 arc4random(), arc4random() & 0xFFFF, arc4random() & 0x0FFF,
                 (arc4random() & 0x3FFF) | 0x8000, arc4random(), arc4random() & 0xFFFF);
        if (rdpPath[0]) {
            DirEntry e;
            uint32_t st = stat_path(ctx, devId, rdpPath, &e);
            if (st && http_code_for(st) == 404) {
                uint32_t fid = 0;
                st = open_file(ctx, devId, rdpPath, WD_FILE_GENERIC_WRITE,
                               WD_FILE_CREATE, WD_OPT_NON_DIRECTORY | WD_OPT_SYNC_IO, &fid, NULL);
                if (st == 0) { close_file(ctx, devId, fid); code = 201; }
            }
            if (st) { respond_failure(fd, req->method, req->path, st); return; }
        }
    }
    char href[WEBDAV_MAX_PATH * 3 + 1];
    if (!rdp_url_path_encode(req->path, href, sizeof(href))) href[0] = '\0';
    XmlBuf x = { 0 };
    xb_printf(&x,
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>"
        "<D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope>"
        "<D:depth>0</D:depth><D:timeout>Second-600</D:timeout>"
        "<D:locktoken><D:href>%s</D:href></D:locktoken>"
        "<D:lockroot><D:href>%s</D:href></D:lockroot>"
        "</D:activelock></D:lockdiscovery></D:prop>", token, href);
    if (x.oom) { free(x.buf); respond_code(fd, 500); return; }
    char hdrs[256];
    snprintf(hdrs, sizeof(hdrs),
             "Lock-Token: <%s>\r\nContent-Type: application/xml; charset=\"utf-8\"\r\n", token);
    http_respond(fd, code, reason_for(code), hdrs, x.buf, x.len);
    free(x.buf);
}

/* ── Connection handler ─────────────────────────────────────────────────── */

/* Ends the exchange: stop sending, read what the client still sends for a
 * moment, then close, so unread bytes do not turn the close into a reset
 * that discards the response. */
static void finish_connection(int fd) {
    shutdown(fd, SHUT_WR);
    struct timeval tv = { 2, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char sink[4096];
    for (int i = 0; i < 256; i++) {
        ssize_t n = read(fd, sink, sizeof(sink));
        if (n <= 0) break;
    }
    close(fd);
}

static void handle_connection(RDPWebDAVServer *srv, int fd) {
    char *buf = (char *)malloc(WEBDAV_HDR_MAX);
    if (!buf) { close(fd); return; }
    size_t len = 0, hdrLen = 0;
    while (len < WEBDAV_HDR_MAX && hdrLen == 0) {
        ssize_t n = read(fd, buf + len, WEBDAV_HDR_MAX - len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        len += (size_t)n;
        hdrLen = header_end(buf, len);
    }
    if (hdrLen == 0) {
        if (len >= WEBDAV_HDR_MAX) respond_code(fd, 431);
        free(buf);
        finish_connection(fd);
        return;
    }

    HttpRequest req;
    int bad = parse_request(buf, hdrLen, srv->authUserPass, &req);
    if (bad) {
        rdp_verbose("webdav: bad request (HTTP %d)", bad);
        respond_code(fd, bad);
        free(buf);
        finish_connection(fd);
        return;
    }
    if (!req.authorized) {
        /* webdavfs asks once without credentials, then answers the challenge
         * with the ones it got through -a; a wrong password is someone else.
         * A body (and 100-continue) is never taken without the password. */
        if (!req.authPresent) {
            rdp_verbose("webdav: %s %s: no drive password, HTTP 401", req.method, req.path);
        } else if (!srv->loggedBadAuth) {
            srv->loggedBadAuth = true;
            rdp_info("webdav: drive \"%s\": refused a request with the wrong password",
                     srv->driveName);
        } else {
            rdp_verbose("webdav: %s %s: wrong drive password, HTTP 401", req.method, req.path);
        }
        http_respond(fd, 401, reason_for(401),
                     "WWW-Authenticate: Basic realm=\"RDP drive\", charset=\"UTF-8\"\r\n",
                     NULL, 0);
        free(buf);
        finish_connection(fd);
        return;
    }
    BodyReader body = { 0 };
    body.fd = fd;
    body.pre = (const uint8_t *)buf + hdrLen;
    body.preLen = len - hdrLen;
    body.left = req.contentLength > 0 ? req.contentLength : 0;
    body.chunked = req.chunked;
    const bool hasBody = req.chunked || req.contentLength > 0;

    rdp_verbose("webdav: %s %s (Depth:%d body:%s)", req.method, req.path, req.depth,
                req.chunked ? "chunked" : hasBody ? "length" : "none");

    if (strcmp(req.method, "PUT") == 0) {
        handle_put(srv, fd, &req, &body);
    } else {
        if (hasBody && req.expectContinue) http_send(fd, "HTTP/1.1 100 Continue\r\n\r\n", 25);
        if (hasBody && !body_drain(&body, WEBDAV_BODY_MAX))
            respond_code(fd, 413);
        else if (strcmp(req.method, "OPTIONS") == 0)
            handle_options(fd);
        else if (strcmp(req.method, "PROPFIND") == 0)
            handle_propfind(srv, fd, &req);
        else if (strcmp(req.method, "GET") == 0)
            handle_get(srv, fd, &req, false);
        else if (strcmp(req.method, "HEAD") == 0)
            handle_get(srv, fd, &req, true);
        else if (strcmp(req.method, "DELETE") == 0)
            handle_delete(srv, fd, &req);
        else if (strcmp(req.method, "MKCOL") == 0)
            handle_mkcol(srv, fd, &req);
        else if (strcmp(req.method, "MOVE") == 0)
            handle_move(srv, fd, &req);
        else if (strcmp(req.method, "LOCK") == 0)
            handle_lock(srv, fd, &req, hasBody);
        else if (strcmp(req.method, "UNLOCK") == 0)
            respond_code(fd, 204);
        else {
            rdp_verbose("webdav: %s not supported", req.method);
            respond_code(fd, 405);
        }
    }
    free(buf);
    finish_connection(fd);
}

/* ── Accept thread ──────────────────────────────────────────────────────── */

static void *accept_thread(void *arg) {
    RDPWebDAVServer *srv = (RDPWebDAVServer *)arg;
    rdp_info("webdav: accept loop started on port %u for drive \"%s\"",
             (unsigned)srv->port, srv->driveName);

    while (srv->running) {
        struct sockaddr_in client;
        socklen_t clientLen = sizeof(client);
        int clientFd = accept(srv->listenFd, (struct sockaddr *)&client, &clientLen);
        if (clientFd < 0) {
            if (!srv->running) break;
            if (errno == EINTR || errno == EAGAIN) continue;
            rdp_verbose("webdav: accept error: %s", strerror(errno));
            break;
        }
        /* No SIGPIPE if Finder hangs up; no thread stuck on a silent client. */
        int one = 1;
        setsockopt(clientFd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        struct timeval tv = { 60, 0 };
        setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(clientFd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        handle_connection(srv, clientFd);
        /* clientFd is closed inside handle_connection. */
    }

    rdp_verbose("webdav: accept loop exiting for drive \"%s\"", srv->driveName);
    return NULL;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void rdp_webdav_drive_label(const char *dosName, char *out, size_t outLen) {
    if (!out || outLen == 0) return;
    snprintf(out, outLen, "%s", (dosName && *dosName) ? dosName : "");
    size_t n = strlen(out);
    while (n > 0 && (out[n - 1] == ':' || out[n - 1] == ' ')) out[--n] = '\0';
    for (size_t i = 0; i < n; i++)
        if (out[i] == '/' || out[i] == ':') out[i] = '_';
    if (n == 0 || strcmp(out, ".") == 0 || strcmp(out, "..") == 0)
        snprintf(out, outLen, "DRIVE");
}

/* Frees the server with its drive password wiped first. */
static void server_free(RDPWebDAVServer *srv) {
    memset_s(srv, sizeof(*srv), 0, sizeof(*srv));
    free(srv);
}

RDPWebDAVServer *rdp_webdav_server_create(freerdp_peer *peer,
                                           uint32_t deviceId,
                                           const char *driveName,
                                           uint16_t port) {
    RDPWebDAVServer *srv = (RDPWebDAVServer *)calloc(1, sizeof(*srv));
    if (!srv) return NULL;

    srv->peer     = peer;
    srv->deviceId = deviceId;
    srv->port     = port;
    /* A fresh drive password (see authPass). */
    uint8_t secret[32];
    arc4random_buf(secret, sizeof(secret));
    for (size_t i = 0; i < sizeof(secret); i++)
        snprintf(srv->authPass + 2 * i, 3, "%02x", secret[i]);
    memset_s(secret, sizeof(secret), 0, sizeof(secret));
    snprintf(srv->authUserPass, sizeof(srv->authUserPass), "%s:%s",
             WEBDAV_AUTH_USER, srv->authPass);
    snprintf(srv->driveName, sizeof(srv->driveName), "%s",
             driveName ? driveName : "DRIVE");
    /* The mount point must be a directory the user owns: /Volumes is root's
     * (755), so the old /Volumes/RDP-<name> mkdir failed silently and
     * mount_webdav exited 2 (ENOENT). The DOS name loses its trailing ':' and
     * spaces ("E:" -> "E"); Finder shows a ':' in a name as '/'. */
    char label[sizeof(srv->driveName)];
    rdp_webdav_drive_label(srv->driveName, label, sizeof(label));
    snprintf(srv->volName, sizeof(srv->volName), "RDP-%s", label);
    const char *home = getenv("HOME");
    const struct passwd *pw = (home && *home) ? NULL : getpwuid(getuid());
    if (pw) home = pw->pw_dir;
    snprintf(srv->mountPoint, sizeof(srv->mountPoint), "%s/RDP-Drives/%s",
             home ? home : "/tmp", label);

    /* Bind the listen socket on 127.0.0.1:<port>. */
    srv->listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv->listenFd < 0) {
        rdp_error("webdav: socket() failed: %s", strerror(errno));
        server_free(srv);
        return NULL;
    }

    int optval = 1;
    setsockopt(srv->listenFd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(srv->listenFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        rdp_error("webdav: bind(%u) failed: %s", (unsigned)port, strerror(errno));
        close(srv->listenFd);
        server_free(srv);
        return NULL;
    }
    /* Port 0 lets the system pick a free one; read back which. */
    socklen_t alen = sizeof(addr);
    if (getsockname(srv->listenFd, (struct sockaddr *)&addr, &alen) == 0)
        srv->port = ntohs(addr.sin_port);

    if (listen(srv->listenFd, 16) < 0) {
        rdp_error("webdav: listen() failed: %s", strerror(errno));
        close(srv->listenFd);
        server_free(srv);
        return NULL;
    }

    srv->running = true;
    if (pthread_create(&srv->acceptThread, NULL, accept_thread, srv) != 0) {
        rdp_error("webdav: pthread_create failed: %s", strerror(errno));
        srv->running = false;
        close(srv->listenFd);
        server_free(srv);
        return NULL;
    }

    rdp_info("webdav: server created for drive \"%s\" on port %u (mount at %s)",
             srv->driveName, (unsigned)port, srv->mountPoint);
    return srv;
}

void rdp_webdav_server_destroy(RDPWebDAVServer *srv) {
    if (!srv) return;
    srv->running = false;
    /* Closing the listen socket will unblock accept() with EBADF/EINVAL. */
    if (srv->listenFd >= 0) {
        close(srv->listenFd);
        srv->listenFd = -1;
    }
    pthread_join(srv->acceptThread, NULL);
    server_free(srv);
}

/* Start a helper with only stdin/stdout/stderr, plus passFd (> 2) at the same
 * number, its close-on-exec cleared in the child. POSIX_SPAWN_CLOEXEC_DEFAULT keeps
 * the daemon's sockets (port 3389, the WebDAV listener, the client connection)
 * out of it: a forked mount_webdav inherited them and, when it hung, kept the
 * RDP port bound after the daemon had gone. Returns the pid, or -1 (errno set). */
static pid_t spawn_clean(const char *path, char *const argv[], int passFd) {
    extern char **environ;
    posix_spawnattr_t attr;
    posix_spawn_file_actions_t fa;
    if (posix_spawnattr_init(&attr) != 0) return -1;
    if (posix_spawn_file_actions_init(&fa) != 0) { posix_spawnattr_destroy(&attr); return -1; }
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);
    for (int fd = 0; fd <= 2; fd++) posix_spawn_file_actions_addinherit_np(&fa, fd);
    if (passFd > 2) posix_spawn_file_actions_addinherit_np(&fa, passFd);
    pid_t pid = -1;
    int rc = posix_spawn(&pid, path, &fa, &attr, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    if (rc != 0) { errno = rc; return -1; }
    return pid;
}

/* mount_webdav's -a <fd>: webdavfs reads the credentials from a seekable file
 * (it seeks to the start first, so a pipe fails) as five fields, each a 32-bit
 * big-endian length and that many bytes: user, password, proxy user, proxy
 * password, certificate chain. The file is unlinked at once, so the password
 * never has a name on disk, and webdavfs zeroes it after reading. Returns the
 * fd (close-on-exec), or -1 with errno set. */
static int make_credentials_fd(const char *user, const char *pass) {
    char dir[1024];
    size_t dl = confstr(_CS_DARWIN_USER_TEMP_DIR, dir, sizeof(dir));
    if (dl == 0 || dl > sizeof(dir)) snprintf(dir, sizeof(dir), "/tmp/");
    char path[1100];
    snprintf(path, sizeof(path), "%s%smacrdp-cred.XXXXXX", dir,
             dir[strlen(dir) - 1] == '/' ? "" : "/");
    int fd = mkostemp(path, O_CLOEXEC);
    if (fd < 0) return -1;
    unlink(path);
    const char *field[4] = { user, pass, "", "" };
    uint8_t buf[4 * (4 + 255) + 4];
    size_t off = 0;
    for (int i = 0; i < 4; i++) {
        size_t l = strlen(field[i]);
        if (l > 255) { close(fd); errno = ENAMETOOLONG; return -1; }  /* webdavfs: < 256 */
        uint32_t be = htonl((uint32_t)l);
        memcpy(buf + off, &be, 4);
        memcpy(buf + off + 4, field[i], l);
        off += 4 + l;
    }
    memset(buf + off, 0, 4);   /* no certificate chain */
    off += 4;
    ssize_t w = write(fd, buf, off);
    int werr = errno;
    memset_s(buf, sizeof(buf), 0, sizeof(buf));
    if (w != (ssize_t)off) { close(fd); errno = w < 0 ? werr : EIO; return -1; }
    return fd;
}

static bool webdav_mount_sync(RDPWebDAVServer *srv) {
    /* Create ~/RDP-Drives and the mount point; mount_webdav needs it to exist. */
    char parent[sizeof(srv->mountPoint)];
    snprintf(parent, sizeof(parent), "%s", srv->mountPoint);
    char *slash = strrchr(parent, '/');
    if (slash) *slash = '\0';
    if ((mkdir(parent, 0700) != 0 && errno != EEXIST) ||
        (mkdir(srv->mountPoint, 0700) != 0 && errno != EEXIST)) {
        rdp_error("webdav: cannot create mount point %s: %s",
                  srv->mountPoint, strerror(errno));
        return false;
    }

    /* Build the URL: http://127.0.0.1:<port>/ */
    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/", (unsigned)srv->port);

    /* /sbin/mount_webdav -S -a <fd> -v <volume name> <url> <mountpoint>
     * -S = no UI at all (no auth or "server not responding" dialogs); -a = the
     * drive password (make_credentials_fd); -v = the volume name Finder shows.
     * No -s: it refuses Basic over http, and this server is loopback only. */
    int credFd = make_credentials_fd(WEBDAV_AUTH_USER, srv->authPass);
    if (credFd < 0) {
        rdp_error("webdav: cannot hand the drive password to mount_webdav: %s",
                  strerror(errno));
        return false;
    }
    char fdArg[16];
    snprintf(fdArg, sizeof(fdArg), "%d", credFd);
    char *argv[] = { "mount_webdav", "-S", "-a", fdArg, "-v", srv->volName, url,
                     srv->mountPoint, NULL };
    pid_t pid = spawn_clean("/sbin/mount_webdav", argv, credFd);
    int spawnErr = errno;
    close(credFd);
    if (pid < 0) {
        rdp_error("webdav: cannot start mount_webdav: %s", strerror(spawnErr));
        return false;
    }
    srv->mountPid = pid;
    int wstatus = 0;
    while (waitpid(pid, &wstatus, 0) < 0 && errno == EINTR) {}
    srv->mountPid = 0;
    bool ok = WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0;
    if (ok) {
        srv->mounted = true;
        rdp_info("webdav: drive \"%s\" mounted at %s (Finder volume %s)",
                 srv->driveName, srv->mountPoint, srv->volName);
    } else if (WIFSIGNALED(wstatus)) {
        rdp_info("webdav: mount of drive \"%s\" stopped (session ended)", srv->driveName);
    } else {
        rdp_error("webdav: mount_webdav exited with status %d",
                  WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1);
    }
    return ok;
}

static void *mount_thread(void *arg) {
    (void)webdav_mount_sync((RDPWebDAVServer *)arg);
    return NULL;
}

bool rdp_webdav_mount(RDPWebDAVServer *srv) {
    if (!srv || srv->mountStarted) return false;
    if (pthread_create(&srv->mountThread, NULL, mount_thread, srv) != 0) {
        rdp_error("webdav: cannot start the mount thread: %s", strerror(errno));
        return false;
    }
    srv->mountStarted = true;
    return true;
}

/* True if something is mounted exactly at path (not just the folder under it). */
static bool is_mount_point(const char *path) {
    struct statfs sfs;
    return statfs(path, &sfs) == 0 && strcmp(sfs.f_mntonname, path) == 0;
}

void rdp_webdav_unmount(RDPWebDAVServer *srv) {
    if (!srv) return;
    if (srv->mountStarted) {
        /* A mount still waiting on the client can't finish now: stop it. */
        pid_t pid = srv->mountPid;
        if (pid > 0) kill(pid, SIGTERM);
        pthread_join(srv->mountThread, NULL);
        srv->mountStarted = false;
    }
    /* Also catches a mount that came up as mount_webdav was being stopped. */
    if (!srv->mounted && !is_mount_point(srv->mountPoint)) return;
    srv->mounted = false;

    /* The client is gone, so nothing can be flushed to it: force the unmount
     * rather than let diskutil wait on a server that can't answer. */
    char *argv[] = { "diskutil", "unmount", "force", srv->mountPoint, NULL };
    pid_t pid = spawn_clean("/usr/sbin/diskutil", argv, -1);
    if (pid > 0) { int st; while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {} }
    else rdp_error("webdav: cannot start diskutil: %s", strerror(errno));

    rmdir(srv->mountPoint);
    rdp_info("webdav: drive \"%s\" unmounted from %s", srv->driveName, srv->mountPoint);
}
