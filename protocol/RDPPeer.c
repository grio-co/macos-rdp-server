#define RDP_LOG_COMPONENT "peer"
#include "logging/RDPLog.h"
#include "protocol/RDPPeer.h"
#include "protocol/RDPWebDAV.h"
#include "protocol/RDPDrivePath.h"
#include "audio/AudioInput.h"

#include <freerdp/freerdp.h>
#include <freerdp/listener.h>
#include <freerdp/server/rdpgfx.h>
#include <freerdp/server/cliprdr.h>
#include <freerdp/server/rdpsnd.h>
#include <freerdp/server/server-common.h>
#include <freerdp/channels/rdpgfx.h>
#include <freerdp/channels/wtsvc.h>
#include <freerdp/channels/drdynvc.h>
#include <freerdp/session.h>
#include <freerdp/crypto/certificate.h>
#include <freerdp/crypto/privatekey.h>
#include <winpr/ssl.h>
#include <winpr/synch.h>
#include <winpr/wtsapi.h>
#include <winpr/stream.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

/* ── MS-RDPEFS (rdpdr) protocol constants ──────────────────────────────── */
/* Packet ids from MS-RDPEFS specification §2.2.1.1 */
#define RDPDR_CTYP_CORE                  0x4472
#define PAKID_CORE_SERVER_ANNOUNCE       0x496E
#define PAKID_CORE_CLIENTID_CONFIRM      0x4343
#define PAKID_CORE_CLIENT_NAME           0x434E
#define PAKID_CORE_CAPABILITY_REQUEST    0x5350
#define PAKID_CORE_CAPABILITY_RESPONSE   0x4350
#define PAKID_CORE_CLIENT_ANNOUNCE_REPLY 0x4352
#define PAKID_CORE_DEVICE_LIST_ANNOUNCE  0x4441
#define PAKID_CORE_DEVICE_REPLY          0x6472
#define PAKID_CORE_DEVICE_IOCOMPLETION   0x4943   /* IRP I/O completion from client */
#define RDPDR_DTYP_FILESYSTEM            0x00000008
#define RDPDR_DTYP_PRINT                 0x00000004
#define RDPDR_DTYP_SERIAL                0x00000001
#define RDPDR_DTYP_PARALLEL              0x00000002
#define RDPDR_DTYP_SMARTCARD             0x00000020
#define CAP_GENERAL_TYPE                 0x0001
#define CAP_DRIVE_TYPE                   0x0004
#define DRIVE_CAPABILITY_VERSION_02      0x00000002
#define PAKID_CORE_USER_LOGGEDON         0x554C
/* General capability extendedPDU flags (MS-RDPEFS 2.2.2.7.1) */
#define RDPDR_DEVICE_REMOVE_PDUS         0x00000001
#define RDPDR_CLIENT_DISPLAY_NAME_PDU    0x00000002
#define RDPDR_USER_LOGGEDON_PDU          0x00000004
#define RDPDR_VERSION_MAJOR              0x0001
#define RDPDR_VERSION_MINOR              0x000C

/* IRP major function codes (MS-RDPEFS §2.2.1.4) — guard against WinPR
 * redefinition (winpr/ntdef.h or similar may define these). */
#ifndef IRP_MJ_CREATE
#define IRP_MJ_CREATE                    0x00000000
#endif
#ifndef IRP_MJ_CLOSE
#define IRP_MJ_CLOSE                     0x00000002
#endif
#ifndef IRP_MJ_READ
#define IRP_MJ_READ                      0x00000003
#endif
#ifndef IRP_MJ_WRITE
#define IRP_MJ_WRITE                     0x00000004
#endif
#ifndef IRP_MJ_QUERY_INFORMATION
#define IRP_MJ_QUERY_INFORMATION         0x00000005
#endif
#ifndef IRP_MJ_SET_INFORMATION
#define IRP_MJ_SET_INFORMATION           0x00000006
#endif
#ifndef IRP_MJ_DIRECTORY_CONTROL
#define IRP_MJ_DIRECTORY_CONTROL         0x0000000C
#endif

/* IRP minor functions for IRP_MJ_DIRECTORY_CONTROL */
#define IRP_MN_QUERY_DIRECTORY           0x00000001

/* PAKID_CORE_DEVICE_IOREQUEST — client-to-server IRP request packet */
#define PAKID_CORE_DEVICE_IOREQUEST      0x4952

/* IRP_MJ_QUERY_INFORMATION / IRP_MJ_SET_INFORMATION classes */
#define RDPDR_FileBasicInformation       0x00000004  /* timestamps + attrs */
#define RDPDR_FileStandardInformation    0x00000005  /* size + allocation */
#define RDPDR_FileDispositionInformation 0x0000000D  /* mark for deletion */
#define RDPDR_FileRenameInformation      0x0000000A  /* rename / move */
/* Longest drive path sent: 2047 UTF-16 units + NUL. */
#define RDPDR_MAX_PATH_BYTES             4096
#define RDPDR_FileFullDirectoryInformation 0x00000002 /* directory listing */

/* NTSTATUS codes relevant to RDPDR — prefixed to avoid redefinition if WinPR
 * defines the generic STATUS_SUCCESS in its ntstatus.h. */
#define RDPDR_STATUS_SUCCESS             0x00000000
#define RDPDR_STATUS_NO_MORE_FILES       0x80000006  /* end of directory listing */

/* IRP_MJ_CREATE access and disposition constants */
#define RDPDR_GENERIC_READ               0x80000000
#define RDPDR_GENERIC_WRITE              0x40000000
#define RDPDR_FILE_OPEN                  0x00000001
#define RDPDR_FILE_CREATE                0x00000002
#define RDPDR_FILE_OPEN_IF               0x00000003
#define RDPDR_FILE_OVERWRITE_IF          0x00000005
#define RDPDR_FILE_DIRECTORY_FILE        0x00000001
#define RDPDR_FILE_NON_DIRECTORY_FILE    0x00000040
#define RDPDR_DELETE_ON_CLOSE            0x00001000

/* Handshake state for the rdpdr channel */
typedef enum {
    kRdpdrIdle = 0,
    kRdpdrSentAnnounce,
    kRdpdrReceivedName,
    kRdpdrReady,
    kRdpdrError,
} RdpdrHandshakeState;

/* TLS material directory. Defaults to /etc/macos-rdp (root LaunchDaemon model);
 * override with RDP_CERT_DIR when running as a LaunchAgent in the user session,
 * where the cert/key live somewhere the user can read. */
#ifndef RDP_CERT_DIR_DEFAULT
#define RDP_CERT_DIR_DEFAULT "/etc/macos-rdp"
#endif

/* ── Settings ──────────────────────────────────────────────────────────── */

/* Load the server certificate + private key into the peer settings. Without
 * these, the TLS handshake cannot complete and the client aborts with a
 * connection/security error (mstsc 0x904). Returns false if either is missing. */
/* ── Monitor layout helpers ────────────────────────────────────────────── */

/* MS-RDPEDISP 2.2.2.2.1 monitor bounds; GFX surfaces and desktops are UINT16. */
#define RDP_MON_MIN 200
#define RDP_MON_MAX 8192
#define RDP_DESKTOP_MAX 32766

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* FreeRDP keeps these private (libfreerdp/core/capabilities.h and
 * channels/rdpsnd/common/rdpsnd_common.h). */
#define RDP_CAPSET_TYPE_LARGE_POINTER 0x001B   /* MS-RDPBCGR 2.2.7.2.7 */
#define RDP_RDPSND_VERSION_WAVE2      0x08     /* client takes Wave2 PDUs (Windows 8+) */

/* A static channel's opening PDU (cliprdr Monitor Ready, rdpdr Server Announce)
 * goes out once the client has finished connecting, and again if it hasn't
 * answered after this long, up to kChannelHelloTries sends in all. mstsc's
 * channel add-ins only start reading once the connection is up. */
#define kChannelHelloRetryMs 3000
#define kChannelHelloTries   3
static void rdpdr_send_hello(RDPPeerContext *ctx);
static void rdpdr_retry_hello(RDPPeerContext *ctx);
static void peer_log_client(freerdp_peer *peer);

static uint32_t clamp_u32(uint32_t v, uint32_t lo, uint32_t hi) {
    return v < lo ? lo : (v > hi ? hi : v);
}

bool rdp_layout_normalize(RDPMonitorLayout *l) {
    if (!l || l->count == 0 || l->count > RDP_MAX_MONITORS) return false;
    int32_t minX = INT32_MAX, minY = INT32_MAX;
    int primary = -1;
    for (uint32_t i = 0; i < l->count; i++) {
        RDPMonitor *m = &l->monitors[i];
        m->width  = clamp_u32(m->width,  RDP_MON_MIN, RDP_MON_MAX) & ~1u;
        m->height = clamp_u32(m->height, RDP_MON_MIN, RDP_MON_MAX);
        if (m->scale < 100 || m->scale > 500) m->scale = 100;
        if (m->primary) {
            if (primary < 0) primary = (int)i;
            else m->primary = false;            /* exactly one primary */
        }
        if (m->x < minX) minX = m->x;
        if (m->y < minY) minY = m->y;
    }
    if (primary < 0) l->monitors[0].primary = true;
    uint32_t w = 0, h = 0;
    for (uint32_t i = 0; i < l->count; i++) {
        RDPMonitor *m = &l->monitors[i];
        m->x -= minX;                            /* bounding box starts at (0,0) */
        m->y -= minY;
        if ((uint32_t)m->x + m->width  > w) w = (uint32_t)m->x + m->width;
        if ((uint32_t)m->y + m->height > h) h = (uint32_t)m->y + m->height;
    }
    if (w > RDP_DESKTOP_MAX || h > RDP_DESKTOP_MAX) return false;
    l->desktopWidth  = w;
    l->desktopHeight = h;
    return true;
}

bool rdp_layout_equal(const RDPMonitorLayout *a, const RDPMonitorLayout *b) {
    if (a->count != b->count) return false;
    for (uint32_t i = 0; i < a->count; i++) {
        const RDPMonitor *p = &a->monitors[i], *q = &b->monitors[i];
        if (p->x != q->x || p->y != q->y || p->width != q->width ||
            p->height != q->height || p->scale != q->scale ||
            p->primary != q->primary ||
            p->physicalWidthMm != q->physicalWidthMm ||
            p->physicalHeightMm != q->physicalHeightMm)
            return false;
    }
    return true;
}

static bool peer_load_certificate(freerdp_peer *peer) {
    rdpSettings *s = peer->context->settings;

    const char *dir = getenv("RDP_CERT_DIR");
    if (!dir || !*dir) dir = RDP_CERT_DIR_DEFAULT;
    char keyPath[1024], certPath[1024];
    snprintf(keyPath,  sizeof(keyPath),  "%s/server.key", dir);
    snprintf(certPath, sizeof(certPath), "%s/server.crt", dir);

    rdpPrivateKey *key = freerdp_key_new_from_file(keyPath);
    if (!key) {
        rdp_error("could not load private key %s — run gen-tls-cert.sh", keyPath);
        return false;
    }
    if (!freerdp_settings_set_pointer_len(s, FreeRDP_RdpServerRsaKey, key, 1)) {
        rdp_error("failed to set server RSA key");
        return false;
    }

    rdpCertificate *cert = freerdp_certificate_new_from_file(certPath);
    if (!cert) {
        rdp_error("could not load certificate %s — run gen-tls-cert.sh", certPath);
        return false;
    }
    if (!freerdp_settings_set_pointer_len(s, FreeRDP_RdpServerCertificate, cert, 1)) {
        rdp_error("failed to set server certificate");
        return false;
    }

    rdp_verbose("loaded TLS certificate and key");
    return true;
}

static void peer_apply_settings(freerdp_peer *peer) {
    rdpSettings *s = peer->context->settings;
    /* Only set what we actually use. Every extra setting is dead weight. */
    freerdp_settings_set_bool(s,   FreeRDP_NetworkAutoDetect,       FALSE);
    freerdp_settings_set_bool(s,   FreeRDP_SupportGraphicsPipeline, TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_GfxH264,                 TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_GfxAVC444,               FALSE);
    freerdp_settings_set_bool(s,   FreeRDP_GfxSmallCache,           FALSE);
    freerdp_settings_set_bool(s,   FreeRDP_GfxThinClient,           FALSE);
    freerdp_settings_set_bool(s,   FreeRDP_RemoteFxCodec,           FALSE);
    /* Security. TLS is always offered unless NLA-only is requested; NLA
     * (CredSSP/NTLM) is added when the session layer found NT hashes in the SAM
     * file (WinPR's NTLM server reads FreeRDP_NtlmSamFile; MD4/RC4 come from the
     * WITH_INTERNAL_MD4/RC4 build). Legacy Standard RDP Security (RC4, no server
     * authentication) is off, as on a current Windows host: offering it lets a
     * man in the middle strip TLS from the negotiation, and every client since
     * Windows XP SP3 does TLS. RDP_LEGACY_SECURITY=1 re-enables it (never in
     * NLA-only mode). */
    const RDPPeerSecurity *sec = &((RDPPeerContext *)peer->context)->callbacks.security;
    bool nla = sec->nlaMode != 0 && sec->samPath && *sec->samPath;
    bool nlaOnly = nla && sec->nlaMode == 2;
    freerdp_settings_set_bool(s,   FreeRDP_UseRdpSecurityLayer,     FALSE);
    const char *legacy = getenv("RDP_LEGACY_SECURITY");
    bool rdpSec = !nlaOnly && legacy && strcmp(legacy, "1") == 0;
    freerdp_settings_set_bool(s,   FreeRDP_RdpSecurity,             rdpSec ? TRUE : FALSE);
    freerdp_settings_set_bool(s,   FreeRDP_TlsSecurity,             nlaOnly ? FALSE : TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_NlaSecurity,             nla ? TRUE : FALSE);
    if (nla) freerdp_settings_set_string(s, FreeRDP_NtlmSamFile, sec->samPath);
    freerdp_settings_set_uint32(s, FreeRDP_TlsSecLevel,             1);
    /* TLS floor: require TLS >= 1.2 for the RDP transport (FreeRDP 3.10.3 applies
     * FreeRDP_TLSMinVersion via SSL_CTX_set_min_proto_version in tls_prepare).
     * RDP_TLS_MIN=1.0|1.1|1.2|1.3 overrides for very old clients. */
    {
        uint16_t minTls = 0x0303;                     /* TLS1_2_VERSION */
        const char *tm = getenv("RDP_TLS_MIN");
        if (tm && *tm) {
            if      (!strcmp(tm, "1.0")) minTls = 0x0301;
            else if (!strcmp(tm, "1.1")) minTls = 0x0302;
            else if (!strcmp(tm, "1.2")) minTls = 0x0303;
            else if (!strcmp(tm, "1.3")) minTls = 0x0304;
            else rdp_error("RDP_TLS_MIN='%s' not recognised (1.0|1.1|1.2|1.3) — using 1.2", tm);
        }
        freerdp_settings_set_uint16(s, FreeRDP_TLSMinVersion, minTls);
    }
    freerdp_settings_set_uint32(s, FreeRDP_ColorDepth,              32);
    freerdp_settings_set_bool(s,   FreeRDP_UnicodeInput,            TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_HasHorizontalWheel,      TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_HasExtendedMouseEvent,   TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_SoundBeepsEnabled,       FALSE);
    /* Multi-monitor ("Use all my monitors" in mstsc): the client's monitor
     * layout arrives in the MCS data and later over DISP; the session gives each
     * monitor its own virtual display and GFX surface (see rdp_peer_set_layout). */
    freerdp_settings_set_bool(s,   FreeRDP_UseMultimon,             TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_SupportMonitorLayoutPdu, TRUE);
    /* No UDP transport here (MS-RDPEMT). FreeRDP offers it by default, and
     * mstsc then spends ~2 s failing to connect over UDP on every logon
     * (client events 1102 -> 1104). */
    freerdp_settings_set_bool(s,   FreeRDP_SupportMultitransport,   FALSE);

    peer_load_certificate(peer);
    rdp_debug("peer settings applied");
}

/* ── Context lifecycle ─────────────────────────────────────────────────── */

static BOOL context_new(freerdp_peer *peer, rdpContext *ctx) {
    RDPPeerContext *c = (RDPPeerContext *)ctx;
    pthread_mutexattr_t mattr;
    pthread_mutexattr_init(&mattr);
    pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&c->xportLock, &mattr);
    rdp_fc_init(&c->fc);
    {
        const char *w = getenv("RDP_GFX_MAX_INFLIGHT");
        int n = w ? atoi(w) : 0;
        if (n >= 1 && n <= 16) c->fc.maxInFlight = (uint32_t)n;
    }
    pthread_mutexattr_destroy(&mattr);
    /* Open the Virtual Channel Manager — all dynamic channels live under it. */
    c->vcm = WTSOpenServerA((LPSTR)peer->context);
    if (!c->vcm || c->vcm == INVALID_HANDLE_VALUE) {
        rdp_error("WTSOpenServerA failed");
        return FALSE;
    }
    rdp_debug("VCM opened");
    return TRUE;
}

static void context_free(freerdp_peer *peer, rdpContext *ctx) {
    (void)peer;
    RDPPeerContext *c = (RDPPeerContext *)ctx;
    /* Unmount and destroy WebDAV servers first — they hold a pointer to the peer
     * which must still be valid when we call destroy. */
    for (int i = 0; i < RDPDR_MAX_DEVICES; i++) {
        if (c->webdavServers[i]) {
            rdp_webdav_unmount(c->webdavServers[i]);
            rdp_webdav_server_destroy(c->webdavServers[i]);
            c->webdavServers[i] = NULL;
        }
    }
    if (c->gfx)    { rdpgfx_server_context_free(c->gfx);    c->gfx    = NULL; }
    if (c->disp)   {
        if (c->dispOpened) (void)c->disp->Close(c->disp);
        disp_server_context_free(c->disp);
        c->disp = NULL;
        c->dispOpened = false;
    }
    /* Fails any paste still waiting on the client, waits for in-flight users, frees the channel. */
    if (c->clip)   { rdp_clip_destroy(c->clip);              c->clip   = NULL; }
    if (c->audioFirstSendMs)
        rdp_info("audio: sent for %llu s, the client confirmed %u block(s)",
                 (unsigned long long)((mono_ms() - c->audioFirstSendMs) / 1000),
                 (unsigned)__atomic_load_n(&c->audioConfirms, __ATOMIC_RELAXED));
    if (c->rdpsnd) { rdpsnd_server_context_free(c->rdpsnd);  c->rdpsnd = NULL; }
    if (c->imaActive) { c->imaActive = false; ima_encoder_free(&c->ima); }
    free(c->imaBuf); c->imaBuf = NULL; c->imaCap = 0;
    /* Audio input (MS-RDPEAI) — close and release the ObjC object. */
    if (c->audioInput) { rdp_audio_input_close(c->audioInput); c->audioInput = NULL; }
    /* Close rdpdr raw WTS channel (opened when RDP_RDPDR_ENABLED=1). */
    if (c->rdpdrChannel && c->rdpdrChannel != INVALID_HANDLE_VALUE) {
        WTSVirtualChannelClose(c->rdpdrChannel);
        c->rdpdrChannel = NULL;
        c->rdpdrEvent   = NULL;
    }
    if (c->vcm)    { WTSCloseServer(c->vcm);                 c->vcm    = NULL; }
    rdp_fc_destroy(&c->fc);
    pthread_mutex_destroy(&c->xportLock);
    rdp_debug("peer context freed");
}

/* ── Input callbacks ───────────────────────────────────────────────────── */

static BOOL peer_keyboard(rdpInput *input, UINT16 flags, UINT8 code) {
    RDPPeerContext *ctx = (RDPPeerContext *)input->context;
    if (ctx->callbacks.onKeyboard)
        ctx->callbacks.onKeyboard(ctx->callbacks.userdata, flags, code);
    return TRUE;
}

static BOOL peer_unicode_keyboard(rdpInput *input, UINT16 flags, UINT16 code) {
    RDPPeerContext *ctx = (RDPPeerContext *)input->context;
    if (ctx->callbacks.onUnicodeKeyboard)
        ctx->callbacks.onUnicodeKeyboard(ctx->callbacks.userdata, flags, code);
    return TRUE;
}

static BOOL peer_mouse(rdpInput *input, UINT16 flags, UINT16 x, UINT16 y) {
    RDPPeerContext *ctx = (RDPPeerContext *)input->context;
    if (ctx->callbacks.onMouse)
        ctx->callbacks.onMouse(ctx->callbacks.userdata, flags, x, y);
    return TRUE;
}

static BOOL peer_mouse_ex(rdpInput *input, UINT16 flags, UINT16 x, UINT16 y) {
    RDPPeerContext *ctx = (RDPPeerContext *)input->context;
    if (ctx->callbacks.onMouseEx)
        ctx->callbacks.onMouseEx(ctx->callbacks.userdata, flags, x, y);
    return TRUE;
}

static BOOL peer_synchronize(rdpInput *input, UINT32 flags) {
    RDPPeerContext *ctx = (RDPPeerContext *)input->context;
    if (ctx->callbacks.onSynchronize)
        ctx->callbacks.onSynchronize(ctx->callbacks.userdata, flags);
    return TRUE;
}

/* FocusIn toggleStates use the same bit layout as KBD_SYNC_*. */
static BOOL peer_focus_in(rdpInput *input, UINT16 toggleStates) {
    return peer_synchronize(input, toggleStates);
}

/* ── GFX caps negotiation ──────────────────────────────────────────────── */

/* (Re)builds the client's graphics output for ctx->layout: deletes the old
 * surfaces, sends ResetGraphics (desktop size + monitor list), then one
 * CreateSurface + MapSurfaceToOutput per monitor. Every new surface has a fresh
 * H.264 decoder on the client, so each waits for a keyframe.
 *
 * ResetGraphics history: an earlier attempt left width/height at 0, and mstsc
 * dropped the connection right after it — a 0x0 output buffer is invalid. The
 * PDU is sent the way Windows, xrdp and FreeRDP's shadow server send it: real
 * desktop size, monitors in desktop (bounding-box) coordinates, right/bottom
 * inclusive, primary flagged. RDP_GFX_RESET=0 restores the old single-surface,
 * no-reset behaviour as an escape hatch.
 *
 * Caller holds xportLock; requires gfxReady && layoutSet. */
static void gfx_rebuild_surfaces_locked(RDPPeerContext *ctx) {
    RdpgfxServerContext *gfx = ctx->gfx;
    const RDPMonitorLayout *l = &ctx->layout;

    for (uint32_t i = 0; i < ctx->surfaceCount; i++) {
        RDPGFX_DELETE_SURFACE_PDU ds = { .surfaceId = ctx->surfaceIds[i] };
        (void)gfx->DeleteSurface(gfx, &ds);
    }
    ctx->surfaceCount = 0;
    /* Frames sent for the old surfaces may never be acked. */
    rdp_fc_reset(&ctx->fc);

    if (!ctx->legacyGfx) {
        MONITOR_DEF defs[RDP_MAX_MONITORS];
        for (uint32_t i = 0; i < l->count; i++) {
            const RDPMonitor *m = &l->monitors[i];
            defs[i].left   = m->x;
            defs[i].top    = m->y;
            defs[i].right  = m->x + (int32_t)m->width  - 1;
            defs[i].bottom = m->y + (int32_t)m->height - 1;
            defs[i].flags  = m->primary ? MONITOR_PRIMARY : 0;
        }
        RDPGFX_RESET_GRAPHICS_PDU rg = {
            .width = l->desktopWidth, .height = l->desktopHeight,
            .monitorCount = l->count, .monitorDefArray = defs,
        };
        UINT rc = gfx->ResetGraphics(gfx, &rg);
        if (rc != CHANNEL_RC_OK)
            rdp_error("ResetGraphics %ux%u (%u monitors) failed: %u",
                      l->desktopWidth, l->desktopHeight, l->count, rc);
    }

    for (uint32_t i = 0; i < l->count; i++) {
        const RDPMonitor *m = &l->monitors[i];
        uint16_t sid = ctx->nextSurfaceId++;
        if (ctx->nextSurfaceId == 0) ctx->nextSurfaceId = 1;

        RDPGFX_CREATE_SURFACE_PDU cs = {
            .surfaceId = sid, .width = (UINT16)m->width, .height = (UINT16)m->height,
            .pixelFormat = GFX_PIXEL_FORMAT_XRGB_8888,
        };
        UINT rc = gfx->CreateSurface(gfx, &cs);
        RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU ms = {
            .surfaceId = sid, .outputOriginX = (UINT32)m->x, .outputOriginY = (UINT32)m->y,
        };
        if (rc == CHANNEL_RC_OK) rc = gfx->MapSurfaceToOutput(gfx, &ms);
        if (rc != CHANNEL_RC_OK)
            rdp_error("GFX surface %u for monitor %u failed: %u", sid, i, rc);

        ctx->surfaceIds[i]               = sid;
        ctx->surfaceKeyframeSent[i]      = false;
        ctx->surfaceKeyframeRequested[i] = true;
        rdp_verbose("GFX surface %u -> monitor %u: %ux%u at (%d,%d)%s",
                    sid, i, m->width, m->height, m->x, m->y,
                    m->primary ? " primary" : "");
    }
    ctx->surfaceCount = l->count;

    if (ctx->callbacks.onKeyframeRequest)
        ctx->callbacks.onKeyframeRequest(ctx->callbacks.userdata, -1);
    ctx->gfxOutputReady = true;
    rdp_info("GFX output ready: %ux%u desktop, %u monitor(s), AVC420%s",
             l->desktopWidth, l->desktopHeight, l->count,
             ctx->legacyGfx ? " (legacy: no ResetGraphics)" : "");
}


/* MS-RDPEGFX FRAME_ACKNOWLEDGE. Runs on the run-loop thread inside the VCM pump
 * (xportLock held); only touches the flow-control state, which has its own lock. */
static UINT gfx_frame_acknowledge(RdpgfxServerContext *gfx,
                                  const RDPGFX_FRAME_ACKNOWLEDGE_PDU *ack) {
    RDPPeerContext *ctx = (RDPPeerContext *)gfx->custom;
    rdp_fc_on_ack(&ctx->fc, ack->frameId, ack->queueDepth, mono_ms());
    return CHANNEL_RC_OK;
}

bool rdp_peer_gfx_can_send(freerdp_peer *peer) {
    if (!peer) return true;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    return rdp_fc_can_send(&ctx->fc, mono_ms());
}

uint32_t rdp_peer_gfx_rate_step(freerdp_peer *peer, bool *changed,
                                uint32_t *maxInFlight, double *latencyMs, uint32_t *skips) {
    if (!peer) { if (changed) *changed = false; return 1000; }
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    return rdp_fc_rate_step(&ctx->fc, changed, maxInFlight, latencyMs, skips);
}

static UINT gfx_caps_advertise(RdpgfxServerContext *gfx,
                                const RDPGFX_CAPS_ADVERTISE_PDU *pdu) {
    RDPPeerContext *ctx = (RDPPeerContext *)gfx->custom;
    rdp_verbose("GFX caps advertise: %u sets", pdu->capsSetCount);

    /* Stack-allocate the capset — capsSet is a pointer in 3.x. */
    RDPGFX_CAPSET capset = {0};
    RDPGFX_CAPS_CONFIRM_PDU confirm = {0};
    confirm.capsSet = &capset;

    /* Walk advertised caps: prefer 8.x (has AVC420), skip anything lower. */
    for (UINT16 i = 0; i < pdu->capsSetCount; i++) {
        rdp_debug("  caps[%u] version=0x%08x flags=0x%08x",
                  i, pdu->capsSets[i].version, pdu->capsSets[i].flags);
        /* Pick the HIGHEST advertised version >= v8 and echo it back VERBATIM
         * (version, length AND flags). Two mstsc requirements learned the hard way
         * from its client event log:
         *   1. The confirmed capset must EXACTLY match one advertised — leaving
         *      length=0 got CapsConfirm rejected (GfxEventConfirmCapsFailed /
         *      0x8007000D), so we copy the whole struct verbatim.
         *   2. Confirming the LOWEST version (v8, flags=0) leaves "AVC available: 0"
         *      and mstsc cannot decode our AVC420 frames (GfxEventDecodingW2S1PduFailed
         *      / 0x8000FFFF). v8.1 / v10.x enable AVC420 by default, so pick the
         *      highest version the client offered. */
        if (pdu->capsSets[i].version >= RDPGFX_CAPVERSION_8 &&
            pdu->capsSets[i].version >= capset.version) {
            capset = pdu->capsSets[i];
        }
    }
    if (!capset.version) {
        rdp_error("client advertised no usable GFX caps version");
        return ERROR_INTERNAL_ERROR;
    }
    rdp_verbose("GFX confirming version=0x%08x flags=0x%08x",
                capset.version, capset.flags);

    UINT rc = gfx->CapsConfirm(gfx, &confirm);
    if (rc != CHANNEL_RC_OK) { rdp_error("CapsConfirm failed: %u", rc); return rc; }

    ctx->gfxReady = true;
    if (ctx->layoutSet)
        gfx_rebuild_surfaces_locked(ctx);
    else
        rdp_info("GFX caps confirmed; surfaces follow once the session sets its layout");
    return CHANNEL_RC_OK;
}

/* ── MS-RDPEDISP (DISPLAY_CONTROL) ─────────────────────────────────────── */

/* The client asks for a new layout (MS-RDPEDISP 2.2.2.2): its window was
 * resized, it went full screen, or its monitors changed. Runs on FreeRDP's disp
 * thread, so it only records the request; the session loop applies it after a
 * debounce (rdp_peer_take_pending_layout). */
static UINT disp_monitor_layout(DispServerContext *context,
                                const DISPLAY_CONTROL_MONITOR_LAYOUT_PDU *pdu) {
    RDPPeerContext *ctx = (RDPPeerContext *)context->custom;
    if (!pdu || pdu->NumMonitors == 0) return CHANNEL_RC_OK;
    if (pdu->NumMonitors > RDP_MAX_MONITORS) {
        rdp_error("disp: %u monitors requested, at most %u supported — ignored",
                  pdu->NumMonitors, RDP_MAX_MONITORS);
        return CHANNEL_RC_OK;
    }

    RDPMonitorLayout l = { .count = pdu->NumMonitors };
    for (UINT32 i = 0; i < pdu->NumMonitors; i++) {
        const DISPLAY_CONTROL_MONITOR_LAYOUT *m = &pdu->Monitors[i];
        l.monitors[i] = (RDPMonitor){
            .x = m->Left, .y = m->Top, .width = m->Width, .height = m->Height,
            .scale = m->DesktopScaleFactor,
            .physicalWidthMm = m->PhysicalWidth, .physicalHeightMm = m->PhysicalHeight,
            .primary = (m->Flags & DISPLAY_CONTROL_MONITOR_PRIMARY) != 0,
        };
        rdp_verbose("disp: monitor %u/%u %ux%u at (%d,%d) scale=%u%%%s",
                    i + 1, pdu->NumMonitors, m->Width, m->Height, m->Left, m->Top,
                    m->DesktopScaleFactor,
                    (m->Flags & DISPLAY_CONTROL_MONITOR_PRIMARY) ? " primary" : "");
    }
    if (!rdp_layout_normalize(&l)) {
        rdp_error("disp: unusable layout requested — ignored");
        return CHANNEL_RC_OK;
    }

    pthread_mutex_lock(&ctx->xportLock);
    ctx->pendingLayout       = l;
    ctx->pendingLayoutValid  = true;
    ctx->pendingLayoutTimeMs = mono_ms();
    pthread_mutex_unlock(&ctx->xportLock);
    rdp_info("disp: client requested %u monitor(s), desktop %ux%u",
             l.count, l.desktopWidth, l.desktopHeight);
    return CHANNEL_RC_OK;
}

static BOOL disp_channel_id_assigned(DispServerContext *context, UINT32 channelId) {
    ((RDPPeerContext *)context->custom)->dispChannelId = channelId;
    return TRUE;
}

/* The client answered a DVC Create Request. For DISP, success means we may now
 * send our caps (max monitors / area), which is what makes the client start
 * sending layouts. Runs inside the VCM pump (run loop, xportLock held): only
 * flag it; the run loop sends after the pump. */
static BOOL dvc_creation_status(void *userdata, UINT32 channelId, INT32 status) {
    RDPPeerContext *ctx = (RDPPeerContext *)userdata;
    if (ctx->disp && channelId == ctx->dispChannelId && channelId != 0) {
        if (status >= 0) {
            ctx->dispCapsPending = true;
            rdp_info("client accepted the display-control channel (status 0x%08x)",
                     (unsigned)status);
        }
        else rdp_info("client declined the display-control channel (0x%08x) — "
                      "dynamic resolution unavailable", (unsigned)status);
    }
    return TRUE;
}

/* ── Audio activated callback ──────────────────────────────────────────── */

/* Preferred client playback rate (Hz) from RDP_AUDIO_RATE, or 0 for "auto".
 *
 * mstsc commonly PLAYS rdpsnd at its 44100 device rate even when it advertises
 * 48000, so a 48000-tagged stream sounds a semitone low (44100/48000 = 0.919 —
 * exactly the reported drop). Preferring 44100 makes captured-rate == play-rate
 * and removes the shift. Gated behind an env var so the rate can be A/B tested
 * on hardware without a rebuild:
 *   "44100" (default) → prefer 44100 stereo 16-bit PCM
 *   "48000"           → prefer 48000
 *   "auto"            → no preference; take the first compatible client format */
static uint32_t rdp_preferred_audio_rate(void) {
    const char *env = getenv("RDP_AUDIO_RATE");
    if (!env || !*env)               return 44100;  /* default */
    if (strcmp(env, "auto") == 0)    return 0;
    long v = strtol(env, NULL, 10);
    if (v == 44100 || v == 48000 || v == 22050) return (uint32_t)v;
    rdp_info("RDP_AUDIO_RATE=\"%s\" not recognized — defaulting to 44100", env);
    return 44100;
}

/* RDP_AUDIO_CODEC: "pcm" (the default; "auto" means the same) sends 16-bit PCM,
 * about 1411 kbps for 44.1 kHz stereo. "ima" also offers IMA ADPCM (4:1, about
 * 353 kbps) to clients that take Wave2 PDUs. IMA is opt-in until a Windows client
 * is heard playing it: in the 2026-11-19 mstsc run the tap had sound and the IMA
 * blocks were valid (Apple's decoder plays them back), yet mstsc stayed silent.
 * PCM is the path mstsc has played. */
static bool rdp_audio_adpcm_allowed(void) {
    const char *e = getenv("RDP_AUDIO_CODEC");
    if (!e || !*e || strcmp(e, "auto") == 0 || strcmp(e, "pcm") == 0) return false;
    if (strcmp(e, "ima") == 0) return true;
    rdp_info("RDP_AUDIO_CODEC=\"%s\" not recognized (pcm|ima) - using pcm", e);
    return false;
}

/* MS-RDPEA Wave Confirm: the client confirms each audio PDU once it has played
 * it. None coming back means it drops what we send. rdpsnd thread. */
static UINT rdpsnd_confirm_block(RdpsndServerContext *context, BYTE blockNo, UINT16 ts) {
    RDPPeerContext *ctx = (RDPPeerContext *)context->data;
    (void)ts;
    if (ctx && __atomic_fetch_add(&ctx->audioConfirms, 1, __ATOMIC_RELAXED) == 0)
        rdp_info("audio: the client confirmed its first audio block (#%u) — it is "
                 "playing what we send", (unsigned)blockNo);
    return CHANNEL_RC_OK;
}

/* A client format we can serve from the server list: same tag/channels/rate/bits
 * as a server format, and for ADPCM a block size our encoder can produce. */
static bool audio_client_format_usable(RdpsndServerContext *r, UINT16 i, bool adpcm) {
    const AUDIO_FORMAT *cf = &r->client_formats[i];
    if (adpcm) {
        if (cf->wFormatTag != WAVE_FORMAT_DVI_ADPCM || cf->nChannels != 2 ||
            cf->wBitsPerSample != 4 || r->clientVersion < 8)   /* Wave2 PDU needed */
            return false;
        int ba = (int)cf->nBlockAlign;
        if (ba < 16 || ba > 8192 || (ba - 8) % 8) return false;
    } else if (cf->wFormatTag != WAVE_FORMAT_PCM) {
        return false;
    }
    for (size_t j = 0; j < r->num_server_formats; j++)
        if (audio_format_compatible(&r->server_formats[j], cf)) return true;
    return false;
}

/* First usable client format of the wanted kind at `rate` (0 = any rate). */
static int audio_find_format(RdpsndServerContext *r, uint32_t rate, bool adpcm) {
    for (UINT16 i = 0; i < r->num_client_formats; i++)
        if ((rate == 0 || r->client_formats[i].nSamplesPerSec == rate) &&
            audio_client_format_usable(r, i, adpcm))
            return (int)i;
    return -1;
}

static void rdpsnd_activated(RdpsndServerContext *rdpsnd) {
    RDPPeerContext *ctx = (RDPPeerContext *)rdpsnd->data;

    /* ── Diagnostics: dump the FULL negotiation so the real client offer is
     * visible in the log (the human reads this to confirm/choose the rate). */
    rdp_info("===== rdpsnd negotiation: %u client format(s) advertised =====",
             (unsigned)rdpsnd->num_client_formats);
    for (UINT16 i = 0; i < rdpsnd->num_client_formats; i++) {
        const AUDIO_FORMAT *cf = &rdpsnd->client_formats[i];
        rdp_info("  client[%u]: %u Hz, %u ch, %u-bit, tag 0x%04x, "
                 "blockAlign %u, avgBytes %u",
                 (unsigned)i, (unsigned)cf->nSamplesPerSec,
                 (unsigned)cf->nChannels, (unsigned)cf->wBitsPerSample,
                 (unsigned)cf->wFormatTag, (unsigned)cf->nBlockAlign,
                 (unsigned)cf->nAvgBytesPerSec);
    }
    rdp_info("----- server advertised %u format(s) -----",
             (unsigned)rdpsnd->num_server_formats);
    for (size_t j = 0; j < rdpsnd->num_server_formats; j++) {
        const AUDIO_FORMAT *sf = &rdpsnd->server_formats[j];
        rdp_info("  server[%zu]: %u Hz, %u ch, %u-bit, tag 0x%04x",
                 j, (unsigned)sf->nSamplesPerSec, (unsigned)sf->nChannels,
                 (unsigned)sf->wBitsPerSample, (unsigned)sf->wFormatTag);
    }

    /* CRITICAL (pitch bug): rdpsnd_server_send_samples() does NOT resample. It
     * encodes the bytes we hand it (described by ctx->rdpsnd->src_format) and
     * tags the WAVE PDU with wFormatNo = selected_client_format — an index into
     * the CLIENT's format list. The client plays our bytes at the SELECTED
     * CLIENT FORMAT's nSamplesPerSec. If that rate differs from the rate we
     * actually produced the PCM at, the client plays it faster/slower → pitch
     * shift.
     *
     * Guarantee src == play rate by (a) selecting a client format at the
     * PREFERRED rate (RDP_AUDIO_RATE, default 44100 — mstsc's usual device
     * rate), (b) pointing src_format at that EXACT client format BEFORE calling
     * SelectFormat (SelectFormat snapshots src_format to compute its
     * bytes-per-frame), and (c) resampling the 48 kHz tap to that negotiated
     * rate in AudioCapture (it polls rdp_peer_get_audio_rate).
     *
     * Two passes: first try to match the preferred rate; if the client offers
     * no compatible format at that rate, fall back to the first compatible
     * format of any rate so audio still works (just possibly shifted). */
    const uint32_t preferred = rdp_preferred_audio_rate();
    rdp_info("audio rate preference: %s (RDP_AUDIO_RATE)",
             preferred ? (preferred == 44100 ? "44100" :
                          preferred == 48000 ? "48000" : "22050") : "auto");

    /* Order: preferred rate (ADPCM, then PCM), then any rate (ADPCM, then PCM).
     * Rate always wins over codec: ADPCM keeps the same rate and channels as the
     * PCM it replaces, so the pitch constraint above holds for both. */
    /* Our IMA ADPCM blocks go out as Wave2 PDUs, which only version 8+
     * clients take; FreeRDP refuses SendSamples2 below that, so an older
     * client would get no sound at all. */
    const bool wave2 = rdpsnd->clientVersion >= RDP_RDPSND_VERSION_WAVE2;
    rdp_info("audio: client rdpsnd version %u%s", (unsigned)rdpsnd->clientVersion,
             wave2 ? "" : " (no Wave2 — PCM only)");
    /* TSSNDCAPS_ALIVE (0x1) says the client will consume audio at all. dwVolume
     * is its current volume: low word left, high word right, 0xFFFF = full. */
    rdp_info("audio: client flags 0x%x (%s), volume L %u%% R %u%%",
             (unsigned)rdpsnd->capsFlags,
             (rdpsnd->capsFlags & 0x1) ? "plays audio" : "NOT alive — it will not play audio",
             (unsigned)((rdpsnd->initialVolume & 0xFFFF) * 100 / 0xFFFF),
             (unsigned)((rdpsnd->initialVolume >> 16) * 100 / 0xFFFF));
    const bool imaAllowed = rdp_audio_adpcm_allowed();
    const bool adpcmOk = imaAllowed && wave2;
    int chosen = -1;
    if (preferred) {
        if (adpcmOk) chosen = audio_find_format(rdpsnd, preferred, true);
        if (chosen < 0) chosen = audio_find_format(rdpsnd, preferred, false);
        if (chosen < 0)
            rdp_info("no compatible client format at preferred %u Hz — "
                     "falling back to first compatible format", preferred);
    }
    if (chosen < 0 && adpcmOk) chosen = audio_find_format(rdpsnd, 0, true);
    if (chosen < 0) chosen = audio_find_format(rdpsnd, 0, false);

    if (chosen < 0) {
        rdp_error("no compatible audio format found among %u client formats",
                  (unsigned)rdpsnd->num_client_formats);
        return;
    }

    const AUDIO_FORMAT *sel = &rdpsnd->client_formats[chosen];
    const bool useIma = (sel->wFormatTag == WAVE_FORMAT_DVI_ADPCM);
    if (useIma) {
        /* src_format describes the PCM we hand over: the server PCM format at
         * the same rate and channels as the chosen client format. */
        const AUDIO_FORMAT *pcmSrc = NULL;
        for (size_t j = 0; j < rdpsnd->num_server_formats; j++) {
            const AUDIO_FORMAT *sf = &rdpsnd->server_formats[j];
            if (sf->wFormatTag == WAVE_FORMAT_PCM && sf->nChannels == sel->nChannels &&
                sf->nSamplesPerSec == sel->nSamplesPerSec) { pcmSrc = sf; break; }
        }
        if (!pcmSrc || ima_encoder_init(&ctx->ima, sel->nChannels, (int)sel->nBlockAlign) != 0) {
            rdp_error("IMA ADPCM setup failed - audio disabled");
            return;
        }
        rdpsnd->src_format = (AUDIO_FORMAT *)pcmSrc;
        ctx->imaActive = true;
    }
    if (!useIma)
    /* Point src_format at the selected client format BEFORE SelectFormat —
     * SelectFormat reads src_format to compute src bytes-per-frame, and it is
     * the format SendSamples describes the PCM with, so it MUST equal the
     * client format we tag the wire with (same rate/ch/bits ⇒ no implicit
     * reinterpretation / pitch shift). */
    rdpsnd->src_format = (AUDIO_FORMAT *)sel;
    UINT rc = rdpsnd->SelectFormat(rdpsnd, (UINT16)chosen);
    if (rc != CHANNEL_RC_OK) {
        rdp_error("SelectFormat(idx %d) failed rc=%u — audio disabled",
                  chosen, (unsigned)rc);
        return;
    }

    /* Confirm SelectFormat actually committed the index we passed: the wire
     * wFormatNo and rdp_peer_get_audio_rate both read selected_client_format,
     * so a mismatch here would mean we resample to one rate but tag another. */
    UINT16 committed = rdpsnd->selected_client_format;
    if (committed != (UINT16)chosen) {
        rdp_error("selected_client_format mismatch: passed %d but context holds "
                  "%u — wire wFormatNo would disagree with resample rate!",
                  chosen, (unsigned)committed);
    }

    ctx->audioReady = true;
    rdp_info("audio codec: %s (RDP_AUDIO_CODEC=%s)",
             useIma ? "IMA ADPCM (4:1)" : "PCM", imaAllowed ? "ima" : "pcm");
    rdp_info("audio format negotiated: client idx %d (committed %u) — "
             "%u Hz, %u ch, %u-bit, tag 0x%04x — wire wFormatNo=%u, "
             "tap will resample to %u Hz (src=play rate)",
             chosen, (unsigned)committed,
             (unsigned)sel->nSamplesPerSec, (unsigned)sel->nChannels,
             (unsigned)sel->wBitsPerSample, (unsigned)sel->wFormatTag,
             (unsigned)committed, (unsigned)sel->nSamplesPerSec);
}

/* Negotiated client playback sample rate (Hz), or 0 if audio is not yet
 * activated. AudioCapture polls this so its resampler targets the exact rate
 * the client plays at — see the pitch-bug note in rdpsnd_activated. */
uint32_t rdp_peer_get_audio_rate(freerdp_peer *peer) {
    if (!peer || !peer->context) return 0;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->rdpsnd || !ctx->audioReady) return 0;
    UINT16 idx = ctx->rdpsnd->selected_client_format;
    if (idx >= ctx->rdpsnd->num_client_formats) return 0;
    return (uint32_t)ctx->rdpsnd->client_formats[idx].nSamplesPerSec;
}

/* ── PostConnect: open virtual channels ───────────────────────────────── */

static BOOL peer_post_connect(freerdp_peer *peer) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    rdp_verbose("post-connect: opening virtual channels");

    /* GFX is a DYNAMIC virtual channel: it can only be opened once drdynvc has
     * reached DRDYNVC_STATE_READY, which does NOT happen until after PostConnect.
     * Opening here fails with "WTSVirtualChannelOpenEx failed" and the client
     * gets no video (black screen). Create the context now; defer Open() to the
     * run loop, which opens it when drdynvc is ready. */
    ctx->gfx = rdpgfx_server_context_new(ctx->vcm);
    if (!ctx->gfx) { rdp_error("rdpgfx_server_context_new failed"); return FALSE; }
    ctx->gfx->custom        = ctx;
    ctx->gfx->CapsAdvertise = gfx_caps_advertise;
    ctx->gfx->FrameAcknowledge = gfx_frame_acknowledge;
    ctx->nextSurfaceId      = 1;
    {
        const char *gr = getenv("RDP_GFX_RESET");
        ctx->legacyGfx = (gr && strcmp(gr, "0") == 0);
        if (ctx->legacyGfx)
            rdp_info("RDP_GFX_RESET=0: legacy GFX (one surface, no ResetGraphics, "
                     "no dynamic resolution or multi-monitor)");
    }
    /* External-thread mode: do NOT let GFX spawn its own thread. The default
     * (ownThread=TRUE) runs an internal loop calling rdpgfx_server_handle_messages
     * — which would race our run-loop's own handle_messages call and the encoder
     * thread's SurfaceCommand on the shared send_stream/zgfx state (heap
     * corruption / SIGABRT). With external mode WE are the sole driver, and a
     * mutex serializes the run loop vs the encoder. */
    if (ctx->gfx->Initialize)
        ctx->gfx->Initialize(ctx->gfx, TRUE);
    rdp_verbose("GFX context created (external-thread mode); open deferred");

    /* MS-RDPEDISP DISPLAY_CONTROL: lets the client resize the session (window
     * resize, full screen, monitor changes). Like GFX it is a DVC, so Open() is
     * deferred to the run loop until drdynvc is READY, and our caps go out once
     * the client accepts the channel (dvc_creation_status). */
    ctx->disp = ctx->legacyGfx ? NULL : disp_server_context_new(ctx->vcm);
    if (!ctx->disp) {
        if (!ctx->legacyGfx)
            rdp_error("disp_server_context_new failed — dynamic resolution unavailable");
    } else {
        ctx->disp->custom            = ctx;
        ctx->disp->rdpcontext        = peer->context;
        ctx->disp->DispMonitorLayout = disp_monitor_layout;
        ctx->disp->ChannelIdAssigned = disp_channel_id_assigned;
        ctx->disp->MaxNumMonitors        = RDP_MAX_MONITORS;
        /* MS-RDPEDISP 2.2.2.1: max area = A x B x MaxNumMonitors pixels. */
        ctx->disp->MaxMonitorAreaFactorA = 8192;
        ctx->disp->MaxMonitorAreaFactorB = 8192;
        WTSVirtualChannelManagerSetDVCCreationCallback(ctx->vcm, dvc_creation_status, ctx);
        rdp_verbose("DISP context created; open deferred");
    }

    /* Clipboard (MS-RDPECLIP) — protocol engine lives in protocol/RDPClipboard.c. */
    ctx->clip = rdp_clip_create(ctx);

    /* RDPDR drive-redirection static VC. Gated behind RDP_RDPDR_ENABLED=1. The
     * channel open is best-effort: if the client didn't advertise "rdpdr" in its
     * channel list, WTSVirtualChannelOpen returns NULL and we log + continue. */
    rdp_peer_open_rdpdr(peer);

    /* Audio. Advertise raw PCM stereo 16-bit at the standard rates mstsc
     * expects (48000 / 44100 / 22050), plus, with RDP_AUDIO_CODEC=ima, the same
     * rates as IMA ADPCM. Only PCM and IMA ADPCM are offered: nothing else can
     * be produced here (FreeRDP's own ADPCM/MS-ADPCM encoders are compiled out
     * and broken in this build, so IMA is encoded by audio/ImaAdpcm.c).
     *
     * Why multiple rates (the pitch fix): rdpsnd_server_send_samples() does not
     * resample — the client plays our bytes at the SELECTED CLIENT FORMAT's
     * rate. mstsc frequently prefers 44100, so advertising only 48000 either
     * fails to match (silence) or, worse, ends up with the client replaying
     * 48000 bytes at 44100 → upward pitch shift. By offering the standard rates
     * we let a clean PCM format match; rdpsnd_activated then points src_format
     * at the selected client format and AudioCapture resamples the 48 kHz tap to
     * that exact rate (rdp_peer_get_audio_rate), so captured rate == play rate.
     *
     * rdpsnd_activated PREFERS the RDP_AUDIO_RATE rate (default 44100 — mstsc's
     * usual playback device rate) when the client offers it, falling back to the
     * first compatible format otherwise; list order here is no longer the
     * tie-breaker, but all three rates must be advertised so the preferred one
     * can match. Must be heap-allocated: rdpsnd_server_context_free() calls
     * free() on server_formats, so a static array would crash on teardown. */
    ctx->rdpsnd = rdpsnd_server_context_new(ctx->vcm);
    if (ctx->rdpsnd) {
        static const UINT32 kRates[] = { 48000, 44100, 22050 };
        const size_t nRates = sizeof(kRates) / sizeof(kRates[0]);
        /* PCM first, then (with RDP_AUDIO_CODEC=ima) the same rates as IMA
         * ADPCM with the standard Windows block size. The ADPCM entries carry
         * cbSize=2 + samples-per-block as WAVEFORMATEX requires; the data
         * pointers are static (FreeRDP frees only the array). */
        static BYTE imaExtra[3][2];
        const bool withIma = rdp_audio_adpcm_allowed();
        const size_t nFmt = withIma ? 2 * nRates : nRates;
        AUDIO_FORMAT *pcm = (AUDIO_FORMAT *)calloc(nFmt, sizeof(AUDIO_FORMAT));
        if (pcm) {
            for (size_t k = 0; k < nRates; k++) {
                pcm[k].wFormatTag      = WAVE_FORMAT_PCM;
                pcm[k].nChannels       = 2;
                pcm[k].nSamplesPerSec  = kRates[k];
                pcm[k].nAvgBytesPerSec = kRates[k] * 2 * 2;
                pcm[k].nBlockAlign     = 2 * 2;
                pcm[k].wBitsPerSample  = 16;
                if (!withIma) continue;
                AUDIO_FORMAT *a = &pcm[nRates + k];
                int ba = ima_block_align(2, kRates[k]);
                int spb = ima_samples_per_block(2, ba);
                imaExtra[k][0] = (BYTE)(spb & 0xFF);
                imaExtra[k][1] = (BYTE)(spb >> 8);
                a->wFormatTag      = WAVE_FORMAT_DVI_ADPCM;
                a->nChannels       = 2;
                a->nSamplesPerSec  = kRates[k];
                a->nBlockAlign     = (UINT16)ba;
                a->nAvgBytesPerSec = (UINT32)((uint64_t)kRates[k] * (uint64_t)ba / (uint64_t)spb);
                a->wBitsPerSample  = 4;
                a->cbSize          = 2;
                a->data            = imaExtra[k];
            }
        }
        ctx->rdpsnd->data               = ctx;
        ctx->rdpsnd->Activated          = rdpsnd_activated;
        ctx->rdpsnd->ConfirmBlock       = rdpsnd_confirm_block;
        ctx->rdpsnd->server_formats     = pcm;
        ctx->rdpsnd->num_server_formats = pcm ? nFmt : 0;
        /* Initial src_format; repointed to the selected client format on
         * activation. Must be non-NULL before SelectFormat (it bounds-checks
         * src_format). */
        ctx->rdpsnd->src_format         = pcm;
        if (ctx->rdpsnd->Initialize(ctx->rdpsnd, TRUE) != CHANNEL_RC_OK) {
            rdp_verbose("audio channel init failed");
            rdpsnd_server_context_free(ctx->rdpsnd);
            ctx->rdpsnd = NULL;
        } else { rdp_verbose("audio channel opened (PCM%s 48000/44100/22050)",
                             withIma ? " + IMA ADPCM" : ""); }
    }

    /* Audio input (MS-RDPEAI mic redirection). Gated behind RDP_AUDIO_INPUT=1.
     * Pass ctx->vcm so AudioInput.m never needs to touch the freerdp_peer struct. */
    ctx->audioInput = rdp_audio_input_open(ctx->vcm);
    if (ctx->audioInput)
        rdp_info("audio_input: channel open");

    return TRUE;
}

/* Client minimized / restored its RDP window. mstsc sends Suppress Output
 * (allow=FALSE) on minimize and again (allow=TRUE) on restore. While suppressed
 * we must STOP sending graphics; on restore we must resume AND send a fresh
 * keyframe — the client discarded everything while minimized, so a delta would
 * reference frames it no longer has (black until the next IDR). Without this the
 * window comes back black. */
static BOOL peer_suppress_output(rdpContext *context, BYTE allow,
                                 const RECTANGLE_16 *area) {
    (void)area;
    RDPPeerContext *ctx = (RDPPeerContext *)context;
    if (allow) {
        /* Force a self-contained refresh so the restored window decodes. */
        pthread_mutex_lock(&ctx->xportLock);
        ctx->outputSuppressed = false;
        for (uint32_t i = 0; i < ctx->surfaceCount; i++) {
            ctx->surfaceKeyframeSent[i]      = false;
            ctx->surfaceKeyframeRequested[i] = true;
        }
        if (ctx->callbacks.onKeyframeRequest)
            ctx->callbacks.onKeyframeRequest(ctx->callbacks.userdata, -1);
        pthread_mutex_unlock(&ctx->xportLock);
        rdp_verbose("client output ALLOWED (restored) — forcing keyframe");
    } else {
        ctx->outputSuppressed = true;
        rdp_verbose("client output SUPPRESSED (minimized) — pausing frames");
    }
    return TRUE;
}

static BOOL peer_activate(freerdp_peer *peer) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    ctx->activated = true;
    rdpSettings *s = peer->context->settings;
    UINT32 w = freerdp_settings_get_uint32(s, FreeRDP_DesktopWidth);
    UINT32 h = freerdp_settings_get_uint32(s, FreeRDP_DesktopHeight);
    UINT32 d = freerdp_settings_get_uint32(s, FreeRDP_ColorDepth);
    rdp_info("peer activated: %ux%u @%ubpp", w, h, d);

    /* Capture the logon credentials the client sent in the RDP info packet. NLA
     * is OFF (our OpenSSL build lacks md4/NTLM), so mstsc transmits them here in
     * the TLS-protected RDP logon. The session layer validates them against the
     * local macOS account (Authenticator) before granting/taking over a session.
     * NEVER log the password. Username/Domain are safe to log. */
    const char *user   = freerdp_settings_get_string(s, FreeRDP_Username);
    const char *domain = freerdp_settings_get_string(s, FreeRDP_Domain);
    rdp_info("logon credentials received: user=%s domain=%s (password %s)",
             user ? user : "(none)", domain ? domain : "(none)",
             freerdp_settings_get_string(s, FreeRDP_Password) ? "present" : "absent");

    /* A reactivation (Deactivate-Reactivate) calls this again: once is enough. */
    const bool first = !ctx->channelsStarted;
    if (first) peer_log_client(peer);

    if (ctx->callbacks.onReady)
        ctx->callbacks.onReady(ctx->callbacks.userdata, w, h, d);

    /* The static channels' opening PDUs go out only now that the client has
     * finished connecting: mstsc's clipboard and drive add-ins start reading
     * then, and drop anything sent earlier. After onReady, so the clipboard
     * host is attached when the client's first format list arrives. */
    if (first) {
        ctx->channelsStarted = true;
        if (ctx->clip) rdp_clip_start(ctx->clip);
        rdpdr_send_hello(ctx);
    }
    return TRUE;
}

/* One line saying what the client asked for and can do, so client-specific
 * behaviour (mstsc vs FreeRDP) can be diagnosed from the log alone. */
static void peer_log_client(freerdp_peer *peer) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    rdpSettings *s = peer->context->settings;
    static const char *const kStatic[] = { "cliprdr", "rdpsnd", "rdpdr", "drdynvc" };
    char chans[64] = "";
    for (size_t i = 0; i < sizeof(kStatic) / sizeof(kStatic[0]); i++) {
        if (!WTSVirtualChannelManagerIsChannelJoined(ctx->vcm, kStatic[i])) continue;
        size_t len = strlen(chans);
        snprintf(chans + len, sizeof(chans) - len, "%s%s", len ? "," : "", kStatic[i]);
    }
    const BYTE *lp = freerdp_settings_get_pointer_array(s, FreeRDP_ReceivedCapabilities,
                                                        RDP_CAPSET_TYPE_LARGE_POINTER);
    UINT32 lpf = (lp && *lp) ? freerdp_settings_get_uint32(s, FreeRDP_LargePointerFlag) : 0;
    rdp_info("client: build %u, channels [%s], pointer cache %u (color %u), "
             "large pointers %s, max pointer %u px, desktop resize %s, "
             "scale %u%%/%u%%, early caps 0x%x",
             freerdp_settings_get_uint32(s, FreeRDP_ClientBuild), chans,
             freerdp_settings_get_uint32(s, FreeRDP_PointerCacheSize),
             freerdp_settings_get_uint32(s, FreeRDP_ColorPointerCacheSize),
             !(lp && *lp) ? "not offered"
                 : (lpf & LARGE_POINTER_FLAG_96x96) ? "96x96" : "none",
             rdp_peer_max_pointer_dim(peer),
             freerdp_settings_get_bool(s, FreeRDP_DesktopResize) ? "yes" : "no",
             freerdp_settings_get_uint32(s, FreeRDP_DesktopScaleFactor),
             freerdp_settings_get_uint32(s, FreeRDP_DeviceScaleFactor),
             freerdp_settings_get_uint32(s, FreeRDP_EarlyCapabilityFlags));
}

uint32_t rdp_peer_max_pointer_dim(freerdp_peer *peer) {
    rdpSettings *s = peer->context->settings;
    const BYTE *lp = freerdp_settings_get_pointer_array(s, FreeRDP_ReceivedCapabilities,
                                                        RDP_CAPSET_TYPE_LARGE_POINTER);
    if (lp && *lp &&
        (freerdp_settings_get_uint32(s, FreeRDP_LargePointerFlag) & LARGE_POINTER_FLAG_96x96))
        return 96;
    return 32;   /* MS-RDPBCGR 2.2.9.1.1.4.4: 32x32 without the large-pointer caps */
}

/* Save Session Info PDU, logon notification (MS-RDPBCGR 2.2.10.1). A Windows
 * host sends it once the user is logged on, and mstsc waits for it ("login
 * complete") before it resizes the session when its window changes, so
 * without it dynamic resolution and full screen never kick in. */
void rdp_peer_send_logon_info(freerdp_peer *peer) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    rdpUpdate *update = peer->context->update;
    if (ctx->logonInfoSent) return;
    /* Set even when nothing can be sent: it also lets DISP open (run loop). */
    ctx->logonInfoSent = true;
    if (!update || !update->SaveSessionInfo) {
        rdp_error("logon notification unavailable (no SaveSessionInfo)");
        return;
    }
    const char *user = freerdp_settings_get_string(peer->context->settings, FreeRDP_Username);
    /* Local accounts log on to the machine itself, so its short name is the
     * domain, as on a Windows host. */
    char host[256] = "";
    if (gethostname(host, sizeof(host) - 1) != 0) host[0] = '\0';
    char *dot = strchr(host, '.');
    if (dot) *dot = '\0';
    logon_info info = { .sessionId = 1, .username = (char *)(user ? user : ""), .domain = host };
    pthread_mutex_lock(&ctx->xportLock);
    BOOL ok = update->SaveSessionInfo(peer->context, INFO_TYPE_LOGON_LONG, &info);
    pthread_mutex_unlock(&ctx->xportLock);
    if (ok) rdp_info("logon notification sent (user=%s domain=%s)", info.username, info.domain);
    else    rdp_error("logon notification (Save Session Info) could not be sent");
}

/* Read the client's logon credentials from the negotiated peer settings. Valid
 * after peer_activate has run (Activate / onReady). The returned pointers are
 * owned by FreeRDP settings and live as long as the peer; any may be NULL when
 * the client supplied no value. NEVER log *password. */
void rdp_peer_get_credentials(freerdp_peer *peer,
                              const char **username,
                              const char **password,
                              const char **domain) {
    const char *u = NULL, *p = NULL, *dm = NULL;
    if (peer && peer->context) {
        rdpSettings *s = peer->context->settings;
        u  = freerdp_settings_get_string(s, FreeRDP_Username);
        p  = freerdp_settings_get_string(s, FreeRDP_Password);
        dm = freerdp_settings_get_string(s, FreeRDP_Domain);
    }
    if (username) *username = u;
    if (password) *password = p;
    if (domain)   *domain   = dm;
}

/* Logon hook (FreeRDP 3.10.3 libfreerdp/core/peer.c, CONNECTION_STATE_NEGO):
 * invoked once, right after security negotiation. For NLA (`automatic` TRUE)
 * CredSSP has finished by now and nla.c (nla_read_ts_credentials) has stored the
 * client's delegated TSPasswordCreds in this peer's settings as FreeRDP_Domain /
 * FreeRDP_Username / FreeRDP_Password — the SEC_WINNT_AUTH_IDENTITY argument is
 * NOT filled on the server side. The later Client Info PDU (info.c
 * rdp_read_info_string) overwrites those settings, so this is the only place the
 * NLA password can be read. FreeRDP ignores our return value, so a rejection is
 * enforced by the session layer (the callback marks the session Disconnecting).
 * NEVER log the password. */
static BOOL peer_logon(freerdp_peer *peer, const SEC_WINNT_AUTH_IDENTITY *identity,
                       BOOL automatic) {
    (void)identity;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    rdpSettings *s = peer->context->settings;
    uint32_t proto = freerdp_settings_get_uint32(s, FreeRDP_SelectedProtocol);
    if (!ctx->callbacks.onLogon) return TRUE;
    const char *user = NULL, *domain = NULL, *pass = NULL;
    if (automatic) {
        user   = freerdp_settings_get_string(s, FreeRDP_Username);
        domain = freerdp_settings_get_string(s, FreeRDP_Domain);
        pass   = freerdp_settings_get_string(s, FreeRDP_Password);
    }
    return ctx->callbacks.onLogon(ctx->callbacks.userdata, automatic ? true : false,
                                  proto, user, domain, pass) ? TRUE : FALSE;
}

/* ── Public API ────────────────────────────────────────────────────────── */

/* Register FreeRDP's built-in server WTS implementation exactly once, before
 * the first WTSOpenServerA. Without this, WinPR's WTS layer tries to dlopen the
 * external FreeRDS plugin (libfreerds-fdsapi.so, Linux-only, absent on macOS),
 * WTSOpenServerA returns NULL, and every connection dies in context_new with
 * "ContextNew callback failed". The sample server does the same (sfreerdp.c).
 *
 * FreeRDP_InitWtsApi is exported by libfreerdp-server but only declared in an
 * internal header the public SDK does not ship, so we forward-declare it. The
 * signature matches WinPR's INIT_WTSAPI_FN typedef. */
extern const WtsApiFunctionTable *FreeRDP_InitWtsApi(void);

static pthread_once_t g_wts_once = PTHREAD_ONCE_INIT;
static void register_freerdp_wts(void) {
    WTSRegisterWtsApiFunctionTable(FreeRDP_InitWtsApi());
}

freerdp_peer *rdp_peer_create(int fd, const RDPPeerCallbacks *callbacks) {
    winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT);
    pthread_once(&g_wts_once, register_freerdp_wts);
    rdp_verbose("creating peer for fd=%d", fd);

    freerdp_peer *peer = freerdp_peer_new(fd);
    if (!peer) { rdp_error("freerdp_peer_new failed"); return NULL; }

    /* ContextSize (PascalCase in 3.x) replaces context_size. */
    peer->ContextSize  = sizeof(RDPPeerContext);
    peer->ContextNew   = context_new;
    peer->ContextFree  = context_free;

    if (!freerdp_peer_context_new(peer)) {
        rdp_error("freerdp_peer_context_new failed");
        freerdp_peer_free(peer);
        return NULL;
    }

    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (callbacks) ctx->callbacks = *callbacks;

    peer_apply_settings(peer);
    peer->PostConnect = peer_post_connect;
    peer->Activate    = peer_activate;
    peer->Logon       = peer_logon;
    /* Handle minimize/restore (Suppress Output) so the window doesn't come back
     * black. SuppressOutput lives on rdpUpdate in 3.x. */
    peer->context->update->SuppressOutput = peer_suppress_output;

    /* Input is on rdpContext, not on freerdp_peer in 3.x. */
    peer->context->input->KeyboardEvent        = peer_keyboard;
    peer->context->input->UnicodeKeyboardEvent = peer_unicode_keyboard;
    peer->context->input->MouseEvent           = peer_mouse;
    peer->context->input->ExtendedMouseEvent   = peer_mouse_ex;
    peer->context->input->SynchronizeEvent     = peer_synchronize;
    peer->context->input->FocusInEvent         = peer_focus_in;

    if (!peer->Initialize(peer)) {
        rdp_error("peer Initialize failed (TLS handshake error)");
        freerdp_peer_context_free(peer);
        freerdp_peer_free(peer);
        return NULL;
    }

    rdp_verbose("peer initialized");
    return peer;
}

void rdp_peer_destroy(freerdp_peer *peer) {
    if (!peer) return;
    rdp_verbose("destroying peer");
    freerdp_peer_context_free(peer);
    freerdp_peer_free(peer);
}

/*
 * Event-driven run: waits on peer transport handles + VCM channel event
 * rather than spinning. Blocks up to 50ms then returns — caller checks
 * disconnect flag. This replaces the busy-poll loop with proper WaitForMultiple.
 */
bool rdp_peer_run_once(freerdp_peer *peer) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;

    HANDLE events[70] = {0};   /* transport(64) + vcm + gfx + clip + rdpdr + ai_input + spare */
    DWORD  nCount = 0;

    /* Peer transport events (typically 1-2 handles). */
    DWORD n = peer->GetEventHandles(peer, events, 64);
    if (n == 0) { rdp_error("GetEventHandles returned 0"); return false; }
    nCount += n;

    /* VCM channel event (drdynvc, cliprdr, etc.). */
    HANDLE vcmEvent = WTSVirtualChannelManagerGetEventHandle(ctx->vcm);
    if (vcmEvent) events[nCount++] = vcmEvent;

    /* GFX channel event (only once the DVC is actually open). */
    if (ctx->gfx && ctx->gfxOpened) {
        HANDLE gfxEvent = rdpgfx_server_get_event_handle(ctx->gfx);
        if (gfxEvent) events[nCount++] = gfxEvent;
    }

    /* Clipboard channel event. cliprdr is a STATIC virtual channel opened in
     * PostConnect, so its event handle is valid as soon as Open() succeeded —
     * no drdynvc dependency (unlike GFX). We pump it here via the shared run
     * loop instead of cliprdr's own Start() reader thread (which would race the
     * transport against this loop and the encoder thread). WITHOUT this wait +
     * the drain below, cliprdr_server_read is NEVER called, so the client's
     * ClientCapabilities / ClientFormatList / FormatDataRequest /
     * FormatDataResponse PDUs are never read off the wire — copy/paste is dead
     * BOTH directions even though our outbound caps/monitor-ready/format-list
     * were sent fine. THIS was the bug. */
    if (ctx->clip) {
        HANDLE clipEvent = (HANDLE)rdp_clip_event(ctx->clip);
        if (clipEvent) events[nCount++] = clipEvent;
    }

    /* RDPDR static VC event (only when RDP_RDPDR_ENABLED=1 and channel open). */
    if (ctx->rdpdrEvent) events[nCount++] = ctx->rdpdrEvent;

    /* AUDIO_INPUT channel event (only when RDP_AUDIO_INPUT=1 and channel open). */
    HANDLE aiEvent = rdp_audio_input_event(ctx->audioInput);
    if (aiEvent) events[nCount++] = aiEvent;

    DWORD status = WaitForMultipleObjects(nCount, events, FALSE, 50 /*ms*/);
    if (status == WAIT_FAILED) {
        rdp_error("WaitForMultipleObjects failed");
        return false;
    }

    /* Everything below WRITES to the transport (CheckFileDescriptor sends acks +
     * input responses, the VCM pump flushes channel PDUs incl. cliprdr, GFX
     * handle_messages drains/answers). Hold xportLock across the whole section so
     * none of it interleaves with the encoder thread's SurfaceCommand, the audio
     * thread's SendSamples, or the clipboard thread's ServerFormatList. The 50ms
     * Wait above is deliberately OUTSIDE the lock so we don't starve those threads
     * while idle. */
    bool ok = true;
    pthread_mutex_lock(&ctx->xportLock);

    /* Process peer transport data. */
    if (!peer->CheckFileDescriptor(peer)) {
        rdp_verbose("peer transport closed");
        ok = false;
    }

    /* Dispatch any pending virtual channel messages. This also advances the
     * drdynvc state machine toward READY. */
    if (ok && vcmEvent && WaitForSingleObject(vcmEvent, 0) == WAIT_OBJECT_0) {
        if (!WTSVirtualChannelManagerCheckFileDescriptor(ctx->vcm)) {
            rdp_error("VCM check failed");
            ok = false;
        }
    }

    /* drdynvc is started from inside the VCM check, which the event above runs
     * only when some channel has queued data. Run it once the client is active
     * so the GFX, display-control and audio channels never wait on unrelated
     * traffic (FreeRDP's shadow server does the same). */
    if (ok && peer->activated &&
        WTSVirtualChannelManagerGetDrdynvcState(ctx->vcm) == DRDYNVC_STATE_NONE &&
        WTSVirtualChannelManagerIsChannelJoined(ctx->vcm, DRDYNVC_SVC_CHANNEL_NAME)) {
        if (!WTSVirtualChannelManagerCheckFileDescriptor(ctx->vcm)) {
            rdp_error("VCM check failed (drdynvc start)");
            ok = false;
        }
    }

    /* Open the GFX dynamic virtual channel once drdynvc is READY. GFX cannot be
     * opened in PostConnect (drdynvc isn't up yet) — doing it here is how the
     * shadow server brings up DVCs. Without this the client gets no video. */
    if (ok && ctx->gfx && !ctx->gfxOpened &&
        WTSVirtualChannelManagerGetDrdynvcState(ctx->vcm) == DRDYNVC_STATE_READY) {
        if (ctx->gfx->Open(ctx->gfx)) {
            ctx->gfxOpened = true;
            rdp_info("GFX channel opened (drdynvc ready)");
        } else {
            rdp_error("GFX Open failed despite drdynvc ready");
        }
    }

    /* DISP opens later than GFX: once the client has the logon notification
     * and the first ResetGraphics (the remote monitor layout). That is the
     * order Windows servers use, and mstsc ignored caps sent before them: the
     * FreeRDP client resized, but mstsc never made its window resizable.
     * drdynvc must be READY too. Failure is non-fatal — the client simply
     * can't request resolutions. */
    if (ok && ctx->disp && !ctx->dispOpened && ctx->gfxOutputReady &&
        ctx->logonInfoSent &&
        WTSVirtualChannelManagerGetDrdynvcState(ctx->vcm) == DRDYNVC_STATE_READY) {
        if (ctx->disp->Open(ctx->disp) == CHANNEL_RC_OK) {
            ctx->dispOpened = true;
            rdp_info("DISP channel opened (drdynvc ready)");
        } else {
            rdp_error("DISP Open failed — dynamic resolution unavailable");
            /* Don't retry every 50ms for the life of the session. */
            ctx->dispOpened = true;
        }
    }

    /* The client accepted the DISP channel: advertise our limits so it starts
     * sending monitor layouts. Without this PDU it never does. */
    if (ok && ctx->disp && ctx->dispCapsPending) {
        ctx->dispCapsPending = false;
        UINT rc = ctx->disp->DisplayControlCaps(ctx->disp);
        if (rc == CHANNEL_RC_OK)
            rdp_info("DISP caps sent: up to %u monitors — dynamic resolution on",
                     RDP_MAX_MONITORS);
        else
            rdp_error("DISP caps send failed: %u", rc);
    }

    /* Drain GFX channel messages once the channel is open. */
    if (ok && ctx->gfx && ctx->gfxOpened) {
        HANDLE gfxEvent = rdpgfx_server_get_event_handle(ctx->gfx);
        if (gfxEvent && WaitForSingleObject(gfxEvent, 0) == WAIT_OBJECT_0) {
            rdpgfx_server_handle_messages(ctx->gfx);
        }
    }

    /* Drain clipboard channel messages (and flush deferred clipboard sends). The
     * cliprdr callbacks write responses back over the transport, hence under
     * xportLock, which we hold here. */
    if (ok && ctx->clip) rdp_clip_pump(ctx->clip);

    /* Drain rdpdr static VC messages (RDP_RDPDR_ENABLED=1 only). */
    if (ok && ctx->rdpdrEvent &&
        WaitForSingleObject(ctx->rdpdrEvent, 0) == WAIT_OBJECT_0) {
        rdp_peer_pump_rdpdr(peer);
    }
    if (ok) rdpdr_retry_hello(ctx);

    /* Drain AUDIO_INPUT DATA PDUs and play on Mac speaker (RDP_AUDIO_INPUT=1).
     * rdp_audio_input_pump is a read-only drain — no transport writes — so it
     * does not strictly need xportLock, but we hold it here anyway for a
     * consistent single-threaded pump discipline (mirrors rdpdr). */
    if (ok && ctx->audioInput) {
        if (!aiEvent || WaitForSingleObject(aiEvent, 0) == WAIT_OBJECT_0) {
            rdp_audio_input_pump(ctx->audioInput);
        }
    }

    pthread_mutex_unlock(&ctx->xportLock);
    return ok;
}

/* ── Display layout API ────────────────────────────────────────────────── */

void rdp_peer_get_client_layout(freerdp_peer *peer, RDPMonitorLayout *out) {
    rdpSettings *s = peer->context->settings;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    memset(out, 0, sizeof(*out));

    UINT32 globalScale = freerdp_settings_get_uint32(s, FreeRDP_DesktopScaleFactor);
    UINT32 n = freerdp_settings_get_uint32(s, FreeRDP_MonitorCount);
    BOOL attrs = freerdp_settings_get_bool(s, FreeRDP_HasMonitorAttributes);
    if (n > RDP_MAX_MONITORS) {
        rdp_error("client has %u monitors; serving the first %u", n, RDP_MAX_MONITORS);
        n = RDP_MAX_MONITORS;
    }

    if (n >= 1 && !ctx->legacyGfx) {
        for (UINT32 i = 0; i < n; i++) {
            const rdpMonitor *m = freerdp_settings_get_pointer_array(
                s, FreeRDP_MonitorDefArray, i);
            if (!m) { n = i; break; }
            out->monitors[i] = (RDPMonitor){
                .x = m->x, .y = m->y,
                .width = (uint32_t)(m->width  > 0 ? m->width  : 0),
                .height = (uint32_t)(m->height > 0 ? m->height : 0),
                .scale = (attrs && m->attributes.desktopScaleFactor)
                             ? m->attributes.desktopScaleFactor : globalScale,
                .physicalWidthMm  = attrs ? m->attributes.physicalWidth  : 0,
                .physicalHeightMm = attrs ? m->attributes.physicalHeight : 0,
                .primary = m->is_primary != 0,
            };
        }
        out->count = n;
    }
    if (out->count == 0) {
        out->count = 1;
        out->monitors[0] = (RDPMonitor){
            .width  = freerdp_settings_get_uint32(s, FreeRDP_DesktopWidth),
            .height = freerdp_settings_get_uint32(s, FreeRDP_DesktopHeight),
            .scale  = globalScale,
            .physicalWidthMm  = freerdp_settings_get_uint32(s, FreeRDP_DesktopPhysicalWidth),
            .physicalHeightMm = freerdp_settings_get_uint32(s, FreeRDP_DesktopPhysicalHeight),
            .primary = true,
        };
    }
    if (!rdp_layout_normalize(out)) {
        /* Degenerate input: fall back to one sane monitor. */
        memset(out, 0, sizeof(*out));
        out->count = 1;
        out->monitors[0] = (RDPMonitor){ .width = 1920, .height = 1080, .scale = 100,
                                         .primary = true };
        rdp_layout_normalize(out);
    }
}

uint32_t rdp_peer_set_layout(freerdp_peer *peer, const RDPMonitorLayout *layout) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    RDPMonitorLayout l = *layout;
    if (!rdp_layout_normalize(&l)) {
        rdp_error("rdp_peer_set_layout: invalid layout ignored");
        pthread_mutex_lock(&ctx->xportLock);
        uint32_t e = ctx->layoutEpoch;
        pthread_mutex_unlock(&ctx->xportLock);
        return e;
    }

    pthread_mutex_lock(&ctx->xportLock);
    ctx->layout    = l;
    ctx->layoutSet = true;
    uint32_t epoch = ++ctx->layoutEpoch;
    /* A request identical to what we now serve is satisfied. */
    if (ctx->pendingLayoutValid && rdp_layout_equal(&ctx->pendingLayout, &l))
        ctx->pendingLayoutValid = false;
    rdpSettings *s = peer->context->settings;
    freerdp_settings_set_uint32(s, FreeRDP_DesktopWidth,  l.desktopWidth);
    freerdp_settings_set_uint32(s, FreeRDP_DesktopHeight, l.desktopHeight);
    if (ctx->gfx && ctx->gfxReady)
        gfx_rebuild_surfaces_locked(ctx);
    else
        ctx->surfaceCount = 0;   /* built when the client's GFX caps arrive */
    pthread_mutex_unlock(&ctx->xportLock);
    return epoch;
}

bool rdp_peer_take_pending_layout(freerdp_peer *peer, RDPMonitorLayout *out,
                                  uint32_t debounceMs) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    bool got = false;
    pthread_mutex_lock(&ctx->xportLock);
    if (ctx->pendingLayoutValid &&
        mono_ms() - ctx->pendingLayoutTimeMs >= debounceMs) {
        ctx->pendingLayoutValid = false;
        if (!ctx->layoutSet || !rdp_layout_equal(&ctx->pendingLayout, &ctx->layout)) {
            *out = ctx->pendingLayout;
            got = true;
        }
    }
    pthread_mutex_unlock(&ctx->xportLock);
    return got;
}

bool rdp_peer_send_h264_frame(freerdp_peer *peer,
                               uint32_t epoch, uint32_t monitorIndex,
                               const uint8_t *data, size_t len,
                               uint32_t width, uint32_t height,
                               bool isKeyFrame,
                               uint16_t dirtyX, uint16_t dirtyY,
                               uint16_t dirtyW, uint16_t dirtyH) {
    if (!peer) return false;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;

    /* Everything below reads layout/surface state that the run loop and the
     * session thread change, and ends in a transport write: hold the lock. */
    pthread_mutex_lock(&ctx->xportLock);
    bool ok = true;

    if (!ctx->gfx || !ctx->gfxReady || ctx->surfaceCount == 0) {
        rdp_debug("gfx not ready");
        goto out;
    }
    /* Encoded for a layout we no longer serve, or for a monitor that is gone:
     * its surface no longer exists on the client. */
    if (epoch != ctx->layoutEpoch || monitorIndex >= ctx->surfaceCount) goto out;
    {
        const RDPMonitor *mon = &ctx->layout.monitors[monitorIndex];
        if (width != mon->width || height != mon->height) {
            rdp_debug("frame %ux%u does not match monitor %u (%ux%u) — dropped",
                      width, height, monitorIndex, mon->width, mon->height);
            goto out;
        }
    }

    /* Client minimized: it ignores (and may choke on) graphics while output is
     * suppressed. Drop frames until it restores (which forces fresh keyframes). */
    if (ctx->outputSuppressed) goto out;

    /* Each surface's first frame MUST be a self-contained keyframe: a delta would
     * reference pictures that surface's decoder never got (black / decode error).
     * Drop deltas until a keyframe goes out, asking that encoder for one. */
    if (!ctx->surfaceKeyframeSent[monitorIndex] && !isKeyFrame) {
        if (!ctx->surfaceKeyframeRequested[monitorIndex] &&
            ctx->callbacks.onKeyframeRequest) {
            ctx->surfaceKeyframeRequested[monitorIndex] = true;
            ctx->callbacks.onKeyframeRequest(ctx->callbacks.userdata,
                                             (int32_t)monitorIndex);
            rdp_debug("delta before first keyframe on monitor %u — requested IDR",
                      monitorIndex);
        }
        goto out;
    }
    if (isKeyFrame) {
        ctx->surfaceKeyframeSent[monitorIndex]      = true;
        ctx->surfaceKeyframeRequested[monitorIndex] = false;
    }

    /* Damage region: keyframes refresh the whole surface; deltas claim only the
     * dirty rect, aligned to 16px macroblocks and clamped to the surface (an
     * AVC420 region outside the decoded picture is rejected by the client). */
    RECTANGLE_16 rect;
    if (isKeyFrame || dirtyW == 0 || dirtyH == 0) {
        rect.left = 0; rect.top = 0;
        rect.right = (UINT16)width; rect.bottom = (UINT16)height;
    } else {
        uint32_t left   = dirtyX & ~15u;
        uint32_t top    = dirtyY & ~15u;
        uint32_t right  = ((uint32_t)dirtyX + dirtyW + 15u) & ~15u;
        uint32_t bottom = ((uint32_t)dirtyY + dirtyH + 15u) & ~15u;
        if (right  > width)  right  = width;
        if (bottom > height) bottom = height;
        if (left   >= right)  { left = 0; right = width; }
        if (top    >= bottom) { top = 0;  bottom = height; }
        rect.left = (UINT16)left;   rect.top = (UINT16)top;
        rect.right = (UINT16)right; rect.bottom = (UINT16)bottom;
    }

    /* quantQualityVals MUST be a valid parallel array (NULL crashes the
     * serializer). qp is a QoE hint; qualityVal mirrors FreeRDP's encoder. */
    RDPGFX_H264_QUANT_QUALITY quant = {0};
    quant.qp         = 26;
    quant.qualityVal = (BYTE)(100 - (26 & 0x3F));

    RDPGFX_AVC420_BITMAP_STREAM avc = {0};
    avc.data                  = (BYTE *)data;
    avc.length                = (UINT32)len;
    avc.meta.numRegionRects   = 1;
    avc.meta.regionRects      = &rect;
    avc.meta.quantQualityVals = &quant;

    RDPGFX_SURFACE_COMMAND cmd = {0};
    cmd.surfaceId = ctx->surfaceIds[monitorIndex];
    cmd.codecId   = RDPGFX_CODECID_AVC420;
    /* cmd.format is a FreeRDP COLOR format (color.h), not a GFX wire enum. */
    cmd.format    = PIXEL_FORMAT_BGRX32;
    cmd.right     = (UINT16)width;
    cmd.bottom    = (UINT16)height;
    cmd.length    = (UINT32)len;
    cmd.data      = (BYTE *)data;
    cmd.extra     = &avc;

    /* StartFrame/EndFrame bracket every surface command: mstsc composites on
     * EndFrame, and frame ids drive its acknowledgements. */
    uint32_t fid = ++ctx->frameId;
    RDPGFX_START_FRAME_PDU startFrame = { .frameId = fid };
    RDPGFX_END_FRAME_PDU   endFrame   = { .frameId = fid };

    UINT rc = ctx->gfx->SurfaceFrameCommand(ctx->gfx, &cmd, &startFrame, &endFrame);
    if (rc == CHANNEL_RC_OK) rdp_fc_on_send(&ctx->fc, fid, mono_ms());
    if (rc != CHANNEL_RC_OK) {
        rdp_error("SurfaceFrameCommand failed: %u", rc);
        ok = false;
        goto out;
    }
    rdp_debug("sent %s frame: monitor %u region=(%u,%u)-(%u,%u) len=%zu",
              isKeyFrame ? "key" : "delta", monitorIndex,
              rect.left, rect.top, rect.right, rect.bottom, len);
out:
    pthread_mutex_unlock(&ctx->xportLock);
    return ok;
}

void rdp_peer_send_default_cursor(freerdp_peer *peer) {
    /* Without any pointer update, mstsc renders the cursor coupled to frame
     * redraws (jerky). Advertising the default SYSTEM pointer makes the client
     * draw + move the cursor locally at the mouse's native rate (smooth), like a
     * Windows RDP server. (Showing the actual Mac cursor shapes lag-free would
     * need full color-pointer PDUs built from the captured cursor — a follow-up.) */
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    rdpPointerUpdate *pointer = peer->context->update->pointer;
    if (!pointer || !pointer->PointerSystem) return;
    POINTER_SYSTEM_UPDATE sys = {0};
    sys.type = SYSPTR_DEFAULT;
    pthread_mutex_lock(&ctx->xportLock);
    pointer->PointerSystem(peer->context, &sys);
    pthread_mutex_unlock(&ctx->xportLock);
    rdp_verbose("sent default system pointer (client-side cursor)");
}

/* Cursor cap from CursorCapture (kMaxCursorDim). Anything <= 96px in EITHER
 * dimension still fits a New (color) pointer, which mstsc renders identically
 * to a Large pointer for these sizes; we use New for <=96 and Large beyond. */
#define RDP_CURSOR_NEW_MAX 96

void rdp_peer_send_cursor_shape(freerdp_peer *peer,
                                const uint8_t *bgra, uint32_t w, uint32_t h,
                                uint16_t hotX, uint16_t hotY) {
    if (!peer || !bgra || w == 0 || h == 0) return;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;

    /* Don't push pointers before the client is up: pre-activation the update
     * channel isn't wired, and (like graphics) sends while output is suppressed
     * are pointless. Mirrors rdp_peer_send_h264_frame's readiness gate. */
    if (!ctx->activated) { rdp_debug("cursor: peer not activated"); return; }
    if (ctx->outputSuppressed) return;

    rdpPointerUpdate *pointer = peer->context->update->pointer;
    if (!pointer) return;

    /* A pointer bigger than the client allows is a protocol error to mstsc.
     * CursorCapture already scales to rdp_peer_max_pointer_dim. */
    const uint32_t maxDim = rdp_peer_max_pointer_dim(peer);
    if (w > maxDim || h > maxDim) {
        rdp_error("cursor %ux%u exceeds the client's %u px limit — not sent", w, h, maxDim);
        return;
    }

    /* Clamp hotspot inside the bitmap. */
    if (hotX >= w) hotX = (uint16_t)(w - 1);
    if (hotY >= h) hotY = (uint16_t)(h - 1);

    /* ── Build the XOR (color) mask ───────────────────────────────────────
     * A CLASSIC 24bpp BGR color pointer, which every client renders
     * (MS-RDPBCGR 2.2.9.1.1.4.4). (Pointers once reached mstsc invisible; the
     * cause was an all-transparent capture, see display/CursorCapture.m, not
     * the pointer format.) Layout: 3 bytes/pixel (B,G,R, no
     * alpha), scanlines BOTTOM-UP, each row padded to a 2-byte (WORD) boundary.
     * Our input is top-down BGRA premultiplied, so we emit rows in reverse and
     * drop the alpha byte. Because alpha is premultiplied, (semi-)transparent
     * pixels are already darkened toward black; the AND mask masks them out, so
     * the dropped alpha costs nothing visible. */
    const uint32_t xorBpp = 24;
    uint32_t xorRowBytes = w * 3u;
    xorRowBytes = (xorRowBytes + 1u) & ~1u;          /* pad to 2 bytes (WORD) */
    uint32_t xorLen = xorRowBytes * h;

    /* ── Build the AND (transparency) mask ────────────────────────────────
     * 1bpp, BOTTOM-UP, each scanline padded to a 2-byte boundary. A SET bit
     * means "transparent" (client shows the underlying pixel). Derive it from
     * alpha: a (near-)transparent pixel -> transparent (bit 1), else opaque
     * (bit 0). We treat alpha < 128 as transparent so the dark fringe of
     * premultiplied anti-aliased edges is masked out rather than painted. */
    uint32_t andRowBytes = ((w + 7u) / 8u);
    andRowBytes = (andRowBytes + 1u) & ~1u;          /* pad to 2 bytes */
    uint32_t andLen = andRowBytes * h;

    /* calloc so the WORD-padding bytes at the end of each xor row stay 0. */
    uint8_t *xorData = (uint8_t *)calloc(1, xorLen);
    uint8_t *andData = (uint8_t *)calloc(1, andLen); /* default opaque (0) */
    if (!xorData || !andData) { free(xorData); free(andData); return; }

    for (uint32_t y = 0; y < h; y++) {
        const uint8_t *srcRow = bgra + (size_t)y * (w * 4u);
        /* bottom-up: source row y goes to dest row (h-1-y). */
        uint8_t *dstRow = xorData + (size_t)(h - 1 - y) * xorRowBytes;
        uint8_t *andRow = andData + (size_t)(h - 1 - y) * andRowBytes;
        for (uint32_t x = 0; x < w; x++) {
            const uint8_t *px  = srcRow + (size_t)x * 4;   /* B,G,R,A */
            uint8_t       *dpx = dstRow + (size_t)x * 3;   /* B,G,R   */
            dpx[0] = px[0];
            dpx[1] = px[1];
            dpx[2] = px[2];
            if (px[3] < 128) {   /* BGRA -> A at +3; <128 == (near-)transparent */
                /* MSB-first bit order within each byte. */
                andRow[x / 8] |= (uint8_t)(0x80u >> (x % 8));
            }
        }
    }

    UINT rc = CHANNEL_RC_OK;
    bool ok = false;

    /* A client that gave no pointerCacheSize can't take New Pointer updates
     * (MS-RDPBCGR 2.2.7.1.5); the 24bpp Color Pointer update carries the same
     * masks. */
    const bool newPointerOk =
        freerdp_settings_get_uint32(peer->context->settings, FreeRDP_PointerCacheSize) > 0;

    pthread_mutex_lock(&ctx->xportLock);
    if (!newPointerOk && pointer->PointerColor) {
        POINTER_COLOR_UPDATE upd = {0};
        upd.cacheIndex    = 0;
        upd.hotSpotX      = hotX;
        upd.hotSpotY      = hotY;
        upd.width         = (UINT16)w;
        upd.height        = (UINT16)h;
        upd.lengthAndMask = andLen;
        upd.lengthXorMask = xorLen;
        upd.xorMaskData   = xorData;
        upd.andMaskData   = andData;
        ok = pointer->PointerColor(peer->context, &upd) ? true : false;
    } else if (w <= RDP_CURSOR_NEW_MAX && h <= RDP_CURSOR_NEW_MAX) {
        if (pointer->PointerNew) {
            POINTER_NEW_UPDATE upd = {0};
            upd.xorBpp = (UINT16)xorBpp;
            upd.colorPtrAttr.cacheIndex    = 0;
            upd.colorPtrAttr.hotSpotX      = hotX;
            upd.colorPtrAttr.hotSpotY      = hotY;
            upd.colorPtrAttr.width         = (UINT16)w;
            upd.colorPtrAttr.height        = (UINT16)h;
            upd.colorPtrAttr.lengthAndMask = andLen;
            upd.colorPtrAttr.lengthXorMask = xorLen;
            upd.colorPtrAttr.xorMaskData   = xorData;
            upd.colorPtrAttr.andMaskData   = andData;
            ok = pointer->PointerNew(peer->context, &upd) ? true : false;
        }
    } else if (pointer->PointerLarge) {
        POINTER_LARGE_UPDATE upd = {0};
        upd.xorBpp        = (UINT16)xorBpp;
        upd.cacheIndex    = 0;
        upd.hotSpotX      = hotX;
        upd.hotSpotY      = hotY;
        upd.width         = (UINT16)w;
        upd.height        = (UINT16)h;
        upd.lengthAndMask = andLen;
        upd.lengthXorMask = xorLen;
        upd.xorMaskData   = xorData;
        upd.andMaskData   = andData;
        ok = pointer->PointerLarge(peer->context, &upd) ? true : false;
    }
    pthread_mutex_unlock(&ctx->xportLock);

    free(xorData);
    free(andData);

    if (!ok) rdp_error("cursor send failed (rc=%u, %ux%u)", rc, w, h);
    else     rdp_debug("sent cursor %ux%u hot=(%u,%u) xorBpp=%u xor=%u and=%u",
                       w, h, hotX, hotY, xorBpp, xorLen, andLen);
}

bool rdp_peer_send_bitmap(freerdp_peer *peer,
                           const uint8_t *bgra, uint32_t x, uint32_t y,
                           uint32_t width, uint32_t height) {
    rdpUpdate *update = peer->context->update;
    SURFACE_BITS_COMMAND cmd = {0};
    cmd.destLeft             = (UINT16)x;
    cmd.destTop              = (UINT16)y;
    cmd.destRight            = (UINT16)(x + width);
    cmd.destBottom           = (UINT16)(y + height);
    cmd.bmp.bpp              = 32;
    cmd.bmp.width            = (UINT16)width;
    cmd.bmp.height           = (UINT16)height;
    cmd.bmp.bitmapData       = (BYTE *)bgra;
    cmd.bmp.bitmapDataLength = width * height * 4;
    cmd.bmp.codecID          = RDP_CODEC_ID_NONE;
    return update->SurfaceBits(update->context, &cmd);
}

/* Ten seconds after the first send, say whether the client has confirmed any
 * of it: the one sign on this side that it is really playing. Audio thread. */
static void audio_check_confirms(RDPPeerContext *ctx) {
    const uint64_t now = mono_ms();
    if (!ctx->audioFirstSendMs) { ctx->audioFirstSendMs = now; return; }
    if (ctx->audioConfirmChecked || now - ctx->audioFirstSendMs < 10000) return;
    ctx->audioConfirmChecked = true;
    const uint32_t n = __atomic_load_n(&ctx->audioConfirms, __ATOMIC_RELAXED);
    if (n == 0)
        rdp_error("audio: 10 s of audio sent and the client confirmed none of it — "
                  "it is not playing what we send");
    else
        rdp_info("audio: the client confirmed %u audio block(s) in the first 10 s", n);
}

/* A rejected send used to vanish silently, which looked exactly like "no
 * sound". Log the first one and then every 1000th. Audio thread only. */
static void audio_note_send(RDPPeerContext *ctx, UINT rc) {
    if (rc == CHANNEL_RC_OK) { audio_check_confirms(ctx); return; }
    if (ctx->audioSendFailures++ % 1000 == 0)
        rdp_error("audio: rdpsnd send failed (rc=%u, %u so far)",
                  (unsigned)rc, (unsigned)ctx->audioSendFailures);
}

bool rdp_peer_send_audio(freerdp_peer *peer,
                          const int16_t *samples, uint32_t frame_count) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->rdpsnd || !ctx->audioReady) return false;
    if (ctx->imaActive) {
        /* Encode here (audio thread only), send finished blocks as a Wave2 PDU. */
        size_t need = ima_max_output(&ctx->ima, frame_count);
        if (need == 0) { (void)ima_encode(&ctx->ima, samples, frame_count, NULL, 0); return true; }
        if (ctx->imaCap < need) {
            uint8_t *nb = (uint8_t *)realloc(ctx->imaBuf, need);
            if (!nb) return false;
            ctx->imaBuf = nb; ctx->imaCap = need;
        }
        size_t n = ima_encode(&ctx->ima, samples, frame_count, ctx->imaBuf, ctx->imaCap);
        if (n == 0) return true;
        /* Real timestamps, as a Windows host sends: dwAudioTimeStamp is ms since
         * boot and wTimeStamp its low 16 bits. Zeros make the data look stale. */
        const uint32_t ts = (uint32_t)mono_ms();
        pthread_mutex_lock(&ctx->xportLock);
        UINT rc2 = ctx->rdpsnd->SendSamples2(ctx->rdpsnd, ctx->rdpsnd->selected_client_format,
                                             ctx->imaBuf, n, (UINT16)ts, ts);
        pthread_mutex_unlock(&ctx->xportLock);
        audio_note_send(ctx, rc2);
        return rc2 == CHANNEL_RC_OK;
    }
    /* SendSamples(context, buf, nframes, timestamp) — real 3.x signature.
     * Audio runs on its own capture thread; serialize against the transport. */
    pthread_mutex_lock(&ctx->xportLock);
    UINT rc = ctx->rdpsnd->SendSamples(ctx->rdpsnd, samples, frame_count,
                                       (UINT16)mono_ms());
    pthread_mutex_unlock(&ctx->xportLock);
    audio_note_send(ctx, rc);
    return rc == CHANNEL_RC_OK;
}

RDPClipboard *rdp_peer_get_clipboard(freerdp_peer *peer) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    return ctx ? rdp_clip_retain(ctx->clip) : NULL;
}

/* ── RDPDR (MS-RDPEFS) drive-redirection implementation ─────────────────── */

/* Write a complete wStream PDU to the rdpdr WTS channel.
 * Called under xportLock (transport write). */
static bool rdpdr_write_pdu(HANDLE ch, wStream *s) {
    size_t len     = Stream_GetPosition(s);
    BYTE  *buf     = Stream_Buffer(s);
    ULONG  written = 0;
    BOOL   ok      = WTSVirtualChannelWrite(ch, (PCHAR)buf, (ULONG)len, &written);
    return ok && written == (ULONG)len;
}

static bool rdpdr_send_server_announce(HANDLE ch) {
    /* Header(4) + VersionMajor(2) + VersionMinor(2) + ClientId(4) */
    wStream *s = Stream_New(NULL, 12);
    if (!s) return false;
    Stream_Write_UINT16(s, RDPDR_CTYP_CORE);
    Stream_Write_UINT16(s, PAKID_CORE_SERVER_ANNOUNCE);
    Stream_Write_UINT16(s, RDPDR_VERSION_MAJOR);
    Stream_Write_UINT16(s, RDPDR_VERSION_MINOR);
    Stream_Write_UINT32(s, 1);   /* initial ClientId = 1 */
    bool ok = rdpdr_write_pdu(ch, s);
    Stream_Free(s, TRUE);
    if (ok) rdp_verbose("rdpdr: -> SERVER_ANNOUNCE");
    return ok;
}

static bool rdpdr_send_caps_request(HANDLE ch) {
    /* Header(4) + numCaps(2) + pad(2) + GeneralCap(44) + DriveCap(8) = 60 bytes.
     * The drive set is what Windows servers send to accept redirected drives;
     * printers, ports and smart cards aren't served, so their sets are left out
     * and clients don't announce those devices. */
    wStream *s = Stream_New(NULL, 60);
    if (!s) return false;
    Stream_Write_UINT16(s, RDPDR_CTYP_CORE);
    Stream_Write_UINT16(s, PAKID_CORE_CAPABILITY_REQUEST);
    Stream_Write_UINT16(s, 2);    /* numCapabilities */
    Stream_Write_UINT16(s, 0);    /* padding */
    /* General capability set (MS-RDPEFS §2.2.2.7.1) */
    Stream_Write_UINT16(s, CAP_GENERAL_TYPE);
    Stream_Write_UINT16(s, 44);   /* capabilityLength */
    Stream_Write_UINT32(s, 2);    /* version */
    Stream_Write_UINT32(s, 0);    /* osType */
    Stream_Write_UINT32(s, 0);    /* osVersion */
    Stream_Write_UINT16(s, RDPDR_VERSION_MAJOR);
    Stream_Write_UINT16(s, RDPDR_VERSION_MINOR);
    Stream_Write_UINT32(s, 0x00007fff); /* ioCode1 */
    Stream_Write_UINT32(s, 0);          /* ioCode2 */
    /* USER_LOGGEDON_PDU promises the Server User Logged On PDU, which clients
     * wait for before announcing drives (rdpdr_send_user_logged_on). */
    Stream_Write_UINT32(s, RDPDR_DEVICE_REMOVE_PDUS | RDPDR_CLIENT_DISPLAY_NAME_PDU |
                           RDPDR_USER_LOGGEDON_PDU);  /* extendedPDU */
    Stream_Write_UINT32(s, 0);          /* extraFlags1 */
    Stream_Write_UINT32(s, 0);          /* extraFlags2 */
    Stream_Write_UINT32(s, 0);          /* specialTypeDeviceCap */
    /* Drive capability set (MS-RDPEFS 2.2.2.7.5): header only */
    Stream_Write_UINT16(s, CAP_DRIVE_TYPE);
    Stream_Write_UINT16(s, 8);    /* capabilityLength */
    Stream_Write_UINT32(s, DRIVE_CAPABILITY_VERSION_02);
    bool ok = rdpdr_write_pdu(ch, s);
    Stream_Free(s, TRUE);
    if (ok) rdp_verbose("rdpdr: -> CAPABILITY_REQUEST (general + drive)");
    return ok;
}

/* MS-RDPEFS 2.2.2.5: the user is logged on. Clients that saw
 * RDPDR_USER_LOGGEDON_PDU in our capabilities announce their drives only after
 * this, so without it mstsc never shares a drive. */
static bool rdpdr_send_user_logged_on(HANDLE ch) {
    wStream *s = Stream_New(NULL, 4);
    if (!s) return false;
    Stream_Write_UINT16(s, RDPDR_CTYP_CORE);
    Stream_Write_UINT16(s, PAKID_CORE_USER_LOGGEDON);
    bool ok = rdpdr_write_pdu(ch, s);
    Stream_Free(s, TRUE);
    return ok;
}

static bool rdpdr_send_clientid_confirm(HANDLE ch, uint16_t clientId) {
    wStream *s = Stream_New(NULL, 12);
    if (!s) return false;
    Stream_Write_UINT16(s, RDPDR_CTYP_CORE);
    Stream_Write_UINT16(s, PAKID_CORE_CLIENTID_CONFIRM);
    Stream_Write_UINT16(s, RDPDR_VERSION_MAJOR);
    Stream_Write_UINT16(s, RDPDR_VERSION_MINOR);
    Stream_Write_UINT32(s, (UINT32)clientId);
    bool ok = rdpdr_write_pdu(ch, s);
    Stream_Free(s, TRUE);
    if (ok) rdp_verbose("rdpdr: -> CLIENTID_CONFIRM (clientId=%u)", (unsigned)clientId);
    return ok;
}

static void rdpdr_send_device_reply(HANDLE ch, uint32_t deviceId, uint32_t result) {
    wStream *s = Stream_New(NULL, 12);
    if (!s) return;
    Stream_Write_UINT16(s, RDPDR_CTYP_CORE);
    Stream_Write_UINT16(s, PAKID_CORE_DEVICE_REPLY);
    Stream_Write_UINT32(s, deviceId);
    Stream_Write_UINT32(s, result);
    rdpdr_write_pdu(ch, s);
    Stream_Free(s, TRUE);
}

/* Allocate the next monotonic IRP request id and store a pending entry.
 * cb may be NULL for fire-and-forget.  Returns 0 if the table is full. */
static uint32_t rdpdr_alloc_request(RDPPeerContext *ctx,
                                     uint32_t deviceId, const char *path,
                                     RDPIrpCallback cb, void *userdata) {
    for (int i = 0; i < RDPDR_MAX_PENDING; i++) {
        if (ctx->rdpdrPending[i].requestId == 0) {
            uint32_t rid = ++ctx->rdpdrNextReqId;
            if (rid == 0) rid = ++ctx->rdpdrNextReqId; /* skip id 0 (sentinel) */
            ctx->rdpdrPending[i].requestId = rid;
            ctx->rdpdrPending[i].deviceId  = deviceId;
            ctx->rdpdrPending[i].callback  = cb;
            ctx->rdpdrPending[i].userdata  = userdata;
            strncpy(ctx->rdpdrPending[i].path, path ? path : "",
                    sizeof(ctx->rdpdrPending[i].path) - 1);
            ctx->rdpdrPending[i].path[sizeof(ctx->rdpdrPending[i].path) - 1] = '\0';
            return rid;
        }
    }
    rdp_verbose("rdpdr: pending table full — dropping IRP for dev %u", deviceId);
    return 0;
}

/* Free a slot in the pending table by request id and invoke its callback.
 * payload/payloadLen are the bytes following the IOCOMPLETION fixed header.
 * Returns the device id associated with the request, or 0 if not found. */
static uint32_t rdpdr_free_request(RDPPeerContext *ctx, uint32_t requestId,
                                    uint32_t ioStatus,
                                    const uint8_t *payload, uint32_t payloadLen) {
    for (int i = 0; i < RDPDR_MAX_PENDING; i++) {
        if (ctx->rdpdrPending[i].requestId == requestId) {
            uint32_t       devId = ctx->rdpdrPending[i].deviceId;
            RDPIrpCallback cb    = ctx->rdpdrPending[i].callback;
            void          *ud    = ctx->rdpdrPending[i].userdata;
            rdp_verbose("rdpdr: IRP completion for requestId=%u dev=%u path=\"%s\"",
                        requestId, devId, ctx->rdpdrPending[i].path);
            ctx->rdpdrPending[i].requestId = 0;
            ctx->rdpdrPending[i].callback  = NULL;
            ctx->rdpdrPending[i].userdata  = NULL;
            /* Invoke callback AFTER zeroing the slot so re-entrant alloc is safe. */
            if (cb) cb(ioStatus, payload, payloadLen, ud);
            return devId;
        }
    }
    return 0;
}


/* ── IRP send helpers ─────────────────────────────────────────────────────
 *
 * Each helper writes the DR_DEVICE_IOREQUEST header (MS-RDPEFS 2.2.1.4):
 *   RDPDR_CTYP_CORE(2) + PAKID_CORE_DEVICE_IOREQUEST(2) + DeviceId(4) +
 *   FileId(4) + CompletionId(4) + MajorFunction(4) + MinorFunction(4)
 * = 24 bytes, then the request-specific body.
 */

/* Write the 24-byte DR_DEVICE_IOREQUEST header; the request body follows at
 * once (no padding: an extra 20 bytes shifted every field the client read). */
static void rdpdr_write_irp_header(wStream *s, uint32_t deviceId,
                                    uint32_t fileId, uint32_t rid,
                                    uint32_t majorFn, uint32_t minorFn) {
    Stream_Write_UINT16(s, RDPDR_CTYP_CORE);
    Stream_Write_UINT16(s, PAKID_CORE_DEVICE_IOREQUEST);
    Stream_Write_UINT32(s, deviceId);
    Stream_Write_UINT32(s, fileId);
    Stream_Write_UINT32(s, rid);
    Stream_Write_UINT32(s, majorFn);
    Stream_Write_UINT32(s, minorFn);
}

/* IRP_MJ_CREATE — open a file or directory.
 * path is UTF-8 relative to the drive root: "" for the root, else "\\a\\b"
 * (rdpdr_path_from_url). It goes out as UTF-16LE with its NUL, which
 * PathLength counts (MS-RDPEFS 2.2.1.4.1). */
bool rdpdr_send_create_req(RDPPeerContext *ctx, uint32_t deviceId,
                            const char *path,
                            uint32_t desiredAccess,
                            uint32_t createDisposition,
                            uint32_t createOptions,
                            RDPIrpCallback cb, void *userdata) {
    uint8_t wpath[RDPDR_MAX_PATH_BYTES];
    size_t pathBytes = rdpdr_utf8_to_utf16le(path ? path : "", wpath, sizeof(wpath));
    if (pathBytes == 0) {
        rdp_info("rdpdr: path not sent (not UTF-8 or too long): \"%s\"", path ? path : "");
        return false;
    }
    uint32_t rid = rdpdr_alloc_request(ctx, deviceId, path, cb, userdata);
    if (rid == 0) return false;

    /* DR_CREATE_REQ body (MS-RDPEFS 2.2.1.4.1):
     *   DesiredAccess(4) + AllocationSize(8) + FileAttributes(4) +
     *   ShareAccess(4) + CreateDisposition(4) + CreateOptions(4) +
     *   PathLength(4) + Path(PathLength) */
    wStream *s = Stream_New(NULL, 24 + 32 + pathBytes);
    if (!s) { rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0); return false; }

    rdpdr_write_irp_header(s, deviceId, 0, rid, IRP_MJ_CREATE, 0);
    Stream_Write_UINT32(s, desiredAccess);
    Stream_Write_UINT64(s, 0);            /* AllocationSize = 0 */
    Stream_Write_UINT32(s, 0);            /* FileAttributes = normal */
    Stream_Write_UINT32(s, 3);            /* ShareAccess = read|write */
    Stream_Write_UINT32(s, createDisposition);
    Stream_Write_UINT32(s, createOptions);
    Stream_Write_UINT32(s, (uint32_t)pathBytes);
    Stream_Write(s, wpath, pathBytes);

    bool ok = rdpdr_write_pdu(ctx->rdpdrChannel, s);
    Stream_Free(s, TRUE);
    if (!ok) rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0);
    else rdp_verbose("rdpdr: -> CREATE_REQ dev=%u rid=%u path=\"%s\" access=0x%x disp=%u opts=0x%x",
                     deviceId, rid, path ? path : "", desiredAccess, createDisposition, createOptions);
    return ok;
}

/* IRP_MJ_CLOSE — close a file handle. */
bool rdpdr_send_close_req(RDPPeerContext *ctx, uint32_t deviceId,
                           uint32_t fileId,
                           RDPIrpCallback cb, void *userdata) {
    char label[32];
    snprintf(label, sizeof(label), "close(%u)", fileId);
    uint32_t rid = rdpdr_alloc_request(ctx, deviceId, label, cb, userdata);
    if (rid == 0) return false;

    /* DR_CLOSE_REQ body: just 32 bytes of padding after the IRP header. */
    wStream *s = Stream_New(NULL, 24 + 32);
    if (!s) { rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0); return false; }

    rdpdr_write_irp_header(s, deviceId, fileId, rid, IRP_MJ_CLOSE, 0);
    /* 32 bytes Padding */
    for (int i = 0; i < 8; i++) Stream_Write_UINT32(s, 0);

    bool ok = rdpdr_write_pdu(ctx->rdpdrChannel, s);
    Stream_Free(s, TRUE);
    if (!ok) rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0);
    else rdp_verbose("rdpdr: -> CLOSE_REQ dev=%u fileId=%u rid=%u",
                     deviceId, fileId, rid);
    return ok;
}

/* IRP_MJ_READ — read bytes from an open file. */
bool rdpdr_send_read_req(RDPPeerContext *ctx, uint32_t deviceId,
                          uint32_t fileId, uint64_t offset, uint32_t length,
                          RDPIrpCallback cb, void *userdata) {
    char label[32];
    snprintf(label, sizeof(label), "read(%u)", fileId);
    uint32_t rid = rdpdr_alloc_request(ctx, deviceId, label, cb, userdata);
    if (rid == 0) return false;

    /* DR_READ_REQ body (MS-RDPEFS §2.2.3.3.3):
     *   Length(4) + Offset(8) + Padding(20) */
    wStream *s = Stream_New(NULL, 24 + 32);
    if (!s) { rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0); return false; }

    rdpdr_write_irp_header(s, deviceId, fileId, rid, IRP_MJ_READ, 0);
    Stream_Write_UINT32(s, length);
    Stream_Write_UINT64(s, offset);
    /* Padding: 20 bytes (5 x uint32) */
    for (int i = 0; i < 5; i++) Stream_Write_UINT32(s, 0);

    bool ok = rdpdr_write_pdu(ctx->rdpdrChannel, s);
    Stream_Free(s, TRUE);
    if (!ok) rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0);
    else rdp_verbose("rdpdr: -> READ_REQ dev=%u fileId=%u off=%llu len=%u rid=%u",
                     deviceId, fileId, (unsigned long long)offset, length, rid);
    return ok;
}

/* IRP_MJ_WRITE — write bytes to an open file. */
bool rdpdr_send_write_req(RDPPeerContext *ctx, uint32_t deviceId,
                           uint32_t fileId, uint64_t offset,
                           const uint8_t *data, uint32_t length,
                           RDPIrpCallback cb, void *userdata) {
    char label[32];
    snprintf(label, sizeof(label), "write(%u)", fileId);
    uint32_t rid = rdpdr_alloc_request(ctx, deviceId, label, cb, userdata);
    if (rid == 0) return false;

    /* DR_WRITE_REQ body (MS-RDPEFS §2.2.3.3.4):
     *   Length(4) + Offset(8) + Padding(20) + WriteData(Length) */
    wStream *s = Stream_New(NULL, 24 + 32 + length);
    if (!s) { rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0); return false; }

    rdpdr_write_irp_header(s, deviceId, fileId, rid, IRP_MJ_WRITE, 0);
    Stream_Write_UINT32(s, length);
    Stream_Write_UINT64(s, offset);
    for (int i = 0; i < 5; i++) Stream_Write_UINT32(s, 0); /* padding */
    if (length > 0 && data) Stream_Write(s, data, length);

    bool ok = rdpdr_write_pdu(ctx->rdpdrChannel, s);
    Stream_Free(s, TRUE);
    if (!ok) rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0);
    else rdp_verbose("rdpdr: -> WRITE_REQ dev=%u fileId=%u off=%llu len=%u rid=%u",
                     deviceId, fileId, (unsigned long long)offset, length, rid);
    return ok;
}

/* IRP_MJ_DIRECTORY_CONTROL / IRP_MN_QUERY_DIRECTORY — list a directory.
 * pattern is the search pattern (e.g. "*"); informationClass is
 * FileFullDirectoryInformation (2). */
bool rdpdr_send_query_dir_req(RDPPeerContext *ctx, uint32_t deviceId,
                               uint32_t fileId, const char *pattern,
                               RDPIrpCallback cb, void *userdata) {
    /* InitialQuery carries the pattern; a follow-up (pattern NULL) carries no
     * path, which the client ignores anyway (MS-RDPEFS 2.2.3.3.10). */
    uint8_t wpat[RDPDR_MAX_PATH_BYTES];
    size_t patBytes = 0;
    if (pattern) {
        patBytes = rdpdr_utf8_to_utf16le(pattern, wpat, sizeof(wpat));
        if (patBytes == 0) {
            rdp_info("rdpdr: pattern not sent (not UTF-8 or too long): \"%s\"", pattern);
            return false;
        }
    }
    char label[64];
    snprintf(label, sizeof(label), "querydir(%u,%s)", fileId, pattern ? "first" : "next");
    uint32_t rid = rdpdr_alloc_request(ctx, deviceId, label, cb, userdata);
    if (rid == 0) return false;

    /* DR_DRIVE_QUERY_DIRECTORY_REQ (MS-RDPEFS 2.2.3.3.10):
     *   FsInformationClass(4) + InitialQuery(1) + PathLength(4) + Padding(23) + Path */
    size_t bodySize = 4 + 1 + 4 + 23 + patBytes;
    wStream *s = Stream_New(NULL, 24 + bodySize);
    if (!s) { rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0); return false; }

    rdpdr_write_irp_header(s, deviceId, fileId, rid,
                            IRP_MJ_DIRECTORY_CONTROL, IRP_MN_QUERY_DIRECTORY);
    Stream_Write_UINT32(s, RDPDR_FileFullDirectoryInformation);
    Stream_Write_UINT8(s,  pattern ? 1 : 0);   /* InitialQuery */
    Stream_Write_UINT32(s, (uint32_t)patBytes);
    Stream_Zero(s, 23);                         /* Padding */
    if (patBytes) Stream_Write(s, wpat, patBytes);

    bool ok = rdpdr_write_pdu(ctx->rdpdrChannel, s);
    Stream_Free(s, TRUE);
    if (!ok) rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0);
    else rdp_verbose("rdpdr: -> QUERY_DIR_REQ dev=%u fileId=%u pat=\"%s\" rid=%u",
                     deviceId, fileId, pattern ? pattern : "(next)", rid);
    return ok;
}

/* IRP_MJ_SET_INFORMATION (FileRenameInformation) — rename or move an open
 * file. newPath is relative to the drive root like a CREATE path. */
bool rdpdr_send_rename_req(RDPPeerContext *ctx, uint32_t deviceId,
                            uint32_t fileId, const char *newPath,
                            bool replaceIfExists,
                            RDPIrpCallback cb, void *userdata) {
    uint8_t wpath[RDPDR_MAX_PATH_BYTES];
    size_t nameBytes = rdpdr_utf8_to_utf16le(newPath ? newPath : "", wpath, sizeof(wpath));
    if (nameBytes <= 2) {   /* not UTF-8, too long, or the root */
        rdp_info("rdpdr: rename target not sent: \"%s\"", newPath ? newPath : "");
        return false;
    }
    char label[32];
    snprintf(label, sizeof(label), "rename(%u)", fileId);
    uint32_t rid = rdpdr_alloc_request(ctx, deviceId, label, cb, userdata);
    if (rid == 0) return false;

    /* DR_DRIVE_SET_INFORMATION_REQ (MS-RDPEFS 2.2.3.3.9):
     *   FsInformationClass(4) + Length(4) + Padding(24) + SetBuffer(Length)
     * RDP_FILE_RENAME_INFORMATION (2.2.3.3.9.1):
     *   ReplaceIfExists(1) + RootDirectory(1) = 0 + FileNameLength(4) + FileName */
    uint32_t setLen = (uint32_t)(6 + nameBytes);
    wStream *s = Stream_New(NULL, 24 + 4 + 4 + 24 + setLen);
    if (!s) { rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0); return false; }

    rdpdr_write_irp_header(s, deviceId, fileId, rid, IRP_MJ_SET_INFORMATION, 0);
    Stream_Write_UINT32(s, RDPDR_FileRenameInformation);
    Stream_Write_UINT32(s, setLen);
    Stream_Zero(s, 24);
    Stream_Write_UINT8(s, replaceIfExists ? 1 : 0);
    Stream_Write_UINT8(s, 0);                   /* RootDirectory */
    Stream_Write_UINT32(s, (uint32_t)nameBytes);
    Stream_Write(s, wpath, nameBytes);

    bool ok = rdpdr_write_pdu(ctx->rdpdrChannel, s);
    Stream_Free(s, TRUE);
    if (!ok) rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0);
    else rdp_verbose("rdpdr: -> RENAME_REQ dev=%u fileId=%u to=\"%s\" replace=%d rid=%u",
                     deviceId, fileId, newPath, replaceIfExists ? 1 : 0, rid);
    return ok;
}

/* IRP_MJ_SET_INFORMATION (FileDispositionInformation) — mark file for deletion. */
bool rdpdr_send_delete_req(RDPPeerContext *ctx, uint32_t deviceId,
                            uint32_t fileId,
                            RDPIrpCallback cb, void *userdata) {
    char label[32];
    snprintf(label, sizeof(label), "delete(%u)", fileId);
    uint32_t rid = rdpdr_alloc_request(ctx, deviceId, label, cb, userdata);
    if (rid == 0) return false;

    /* DR_SET_INFORMATION_REQ body (MS-RDPEFS §2.2.3.3.9):
     *   FsInformationClass(4) + Length(4) + Padding(24) + SetBuffer(Length)
     * FileDispositionInformation body: DeleteFile(1) = 1. */
    wStream *s = Stream_New(NULL, 24 + 4 + 4 + 24 + 1);
    if (!s) { rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0); return false; }

    rdpdr_write_irp_header(s, deviceId, fileId, rid, IRP_MJ_SET_INFORMATION, 0);
    Stream_Write_UINT32(s, RDPDR_FileDispositionInformation);
    Stream_Write_UINT32(s, 1);   /* Length of SetBuffer = 1 byte */
    for (int i = 0; i < 6; i++) Stream_Write_UINT32(s, 0); /* 24 bytes padding */
    Stream_Write_UINT8(s,  1);   /* DeleteFile = TRUE */

    bool ok = rdpdr_write_pdu(ctx->rdpdrChannel, s);
    Stream_Free(s, TRUE);
    if (!ok) rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0);
    else rdp_verbose("rdpdr: -> DELETE_REQ dev=%u fileId=%u rid=%u",
                     deviceId, fileId, rid);
    return ok;
}

/* Decode one PDU from the rdpdr channel and advance the state machine. */
static void rdpdr_handle_pdu(RDPPeerContext *ctx, BYTE *buf, ULONG len) {
    wStream stack; /* stack-allocated reader; avoids heap alloc for each PDU */
    wStream *s = Stream_StaticInit(&stack, buf, (size_t)len);

    if (Stream_GetRemainingLength(s) < 4) return;
    if (!ctx->rdpdrHeard) {
        ctx->rdpdrHeard = true;   /* stops SERVER_ANNOUNCE resends */
        rdp_info("rdpdr: client answered — handshake under way");
    }
    UINT16 component, packetId;
    Stream_Read_UINT16(s, component);
    Stream_Read_UINT16(s, packetId);
    if (component != RDPDR_CTYP_CORE) {
        rdp_verbose("rdpdr: unknown component 0x%04x", component);
        return;
    }

    switch (packetId) {

    case PAKID_CORE_CLIENT_ANNOUNCE_REPLY: {
        if (Stream_GetRemainingLength(s) < 8) break;
        UINT16 maj, min; UINT32 cid;
        Stream_Read_UINT16(s, maj);
        Stream_Read_UINT16(s, min);
        Stream_Read_UINT32(s, cid);
        ctx->rdpdrClientId = (uint16_t)(cid & 0xFFFF);
        rdp_verbose("rdpdr: <- CLIENT_ANNOUNCE_REPLY v%u.%u clientId=%u",
                    (unsigned)maj, (unsigned)min, (unsigned)ctx->rdpdrClientId);
        break;
    }

    case PAKID_CORE_CLIENT_NAME: {
        if (Stream_GetRemainingLength(s) < 12) break;
        UINT32 unicodeFlag, codePage, nameLen;
        Stream_Read_UINT32(s, unicodeFlag);
        Stream_Read_UINT32(s, codePage);
        Stream_Read_UINT32(s, nameLen);
        (void)codePage;
        char name[128] = "(empty)";
        if (nameLen > 0 && (size_t)nameLen <= Stream_GetRemainingLength(s)) {
            if (unicodeFlag && nameLen >= 2) {
                size_t chars = (nameLen / 2 < 127) ? nameLen / 2 : 127;
                for (size_t i = 0; i < chars; i++) {
                    UINT16 wc; Stream_Read_UINT16(s, wc);
                    name[i] = (wc && wc < 128) ? (char)wc : '?';
                    if (!wc) { name[i] = '\0'; break; }
                }
                name[chars] = '\0';
            } else {
                size_t n = (nameLen < 127) ? nameLen : 127;
                Stream_Read(s, name, n);
                name[n] = '\0';
            }
        }
        rdp_verbose("rdpdr: <- CLIENT_NAME \"%s\"", name);

        /* Both ANNOUNCE_REPLY and NAME received — send caps + confirm. */
        if (ctx->rdpdrState == kRdpdrSentAnnounce) {
            if (rdpdr_send_caps_request(ctx->rdpdrChannel) &&
                rdpdr_send_clientid_confirm(ctx->rdpdrChannel, ctx->rdpdrClientId)) {
                ctx->rdpdrState = kRdpdrReceivedName;
            } else {
                ctx->rdpdrState = kRdpdrError;
                rdp_error("rdpdr: failed to send caps/confirm");
            }
        }
        break;
    }

    case PAKID_CORE_CAPABILITY_RESPONSE: {
        if (Stream_GetRemainingLength(s) < 4) break;
        UINT16 numCaps, pad;
        Stream_Read_UINT16(s, numCaps);
        Stream_Read_UINT16(s, pad);
        (void)pad;
        /* Walk the sets (CAPABILITY_HEADER: type, length incl. header, version)
         * for the client's extendedPDU flags and whether it can share drives. */
        uint32_t extendedPdu = 0;
        bool haveGeneral = false, drives = false;
        for (UINT16 i = 0; i < numCaps && Stream_GetRemainingLength(s) >= 8; i++) {
            UINT16 type, len;
            UINT32 ver;
            Stream_Read_UINT16(s, type);
            Stream_Read_UINT16(s, len);
            Stream_Read_UINT32(s, ver);
            (void)ver;
            size_t body = len >= 8 ? (size_t)len - 8 : 0;
            if (body > Stream_GetRemainingLength(s)) break;
            if (type == CAP_GENERAL_TYPE && body >= 24) {
                /* osType(4) osVersion(4) major(2) minor(2) ioCode1(4) ioCode2(4) */
                Stream_Seek(s, 20);
                Stream_Read_UINT32(s, extendedPdu);
                Stream_Seek(s, body - 24);
                haveGeneral = true;
            } else {
                if (type == CAP_DRIVE_TYPE) drives = true;
                Stream_Seek(s, body);
            }
        }
        /* Without a parsable general set, assume a current client (it waits). */
        const bool wantsLoggedOn = !haveGeneral || (extendedPdu & RDPDR_USER_LOGGEDON_PDU);
        rdp_info("rdpdr: client capabilities: %u set(s), drives %s, waits for logon %s",
                 (unsigned)numCaps, drives ? "yes" : "no", wantsLoggedOn ? "yes" : "no");
        if (ctx->rdpdrState == kRdpdrReceivedName && wantsLoggedOn &&
            !ctx->rdpdrLoggedOnSent) {
            ctx->rdpdrLoggedOnSent = true;
            if (rdpdr_send_user_logged_on(ctx->rdpdrChannel))
                rdp_info("rdpdr: user logged on sent — the client may now announce drives");
            else
                rdp_error("rdpdr: failed to send user logged on");
        }
        /* Stay in ReceivedName until the device list arrives. */
        break;
    }

    case PAKID_CORE_DEVICE_LIST_ANNOUNCE: {
        if (Stream_GetRemainingLength(s) < 4) break;
        UINT32 deviceCount;
        Stream_Read_UINT32(s, deviceCount);
        rdp_info("rdpdr: <- DEVICE_LIST_ANNOUNCE — %u device(s)", (unsigned)deviceCount);

        /* Track how many drive slots we have filled so we can index webdavServers. */
        int driveSlot = 0;

        for (UINT32 i = 0; i < deviceCount; i++) {
            if (Stream_GetRemainingLength(s) < 20) break;
            UINT32 devType, devId, dataLen;
            char dosName[9] = {0};
            Stream_Read_UINT32(s, devType);
            Stream_Read_UINT32(s, devId);
            Stream_Read(s, dosName, 8);
            dosName[8] = '\0';
            Stream_Read_UINT32(s, dataLen);
            if (dataLen > 0 && (size_t)dataLen <= Stream_GetRemainingLength(s))
                Stream_Seek(s, (size_t)dataLen);

            const char *typeName = "unknown";
            switch (devType) {
                case RDPDR_DTYP_FILESYSTEM: typeName = "drive";     break;
                case RDPDR_DTYP_PRINT:      typeName = "printer";   break;
                case RDPDR_DTYP_SERIAL:     typeName = "serial";    break;
                case RDPDR_DTYP_PARALLEL:   typeName = "parallel";  break;
                case RDPDR_DTYP_SMARTCARD:  typeName = "smartcard"; break;
            }

            if (devType == RDPDR_DTYP_FILESYSTEM) {
                rdp_info("rdpdr: client drive #%u — id=%u name=\"%s\" "
                         "(starting embedded WebDAV server for Finder mount)",
                         (unsigned)i, (unsigned)devId, dosName);

                /* Desktop placeholder for immediate user feedback. */
                rdp_drive_mount_placeholder(dosName, devId);

                /* Start an embedded WebDAV server and mount via mount_webdav. */
                if (driveSlot < RDPDR_MAX_DEVICES) {
                    /* Port 0: the system picks a free loopback port. Fixed
                     * ports (8760 + slot) collided with a second session or
                     * daemon, and the drive then never mounted. */
                    uint16_t port = 0;
                    /* Must release xportLock before calling server_create which
                     * calls pthread_create and may need to call back into IRPs.
                     * ctx->base.peer is the owning freerdp_peer pointer. */
                    freerdp_peer *peerPtr = ctx->base.peer;
                    pthread_mutex_unlock(&ctx->xportLock);
                    RDPWebDAVServer *srv =
                        rdp_webdav_server_create(peerPtr, devId, dosName, port);
                    pthread_mutex_lock(&ctx->xportLock);

                    if (srv) {
                        ctx->webdavServers[driveSlot] = srv;
                        /* Async: mount_webdav's PROPFIND needs the IRP replies
                         * this thread receives, so it must not wait here. */
                        rdp_webdav_mount(srv);
                        rdp_info("rdpdr: WebDAV server started for drive \"%s\"; "
                                 "mounting in the background", dosName);
                    } else {
                        rdp_error("rdpdr: failed to start WebDAV server for drive \"%s\"",
                                  dosName);
                    }
                    driveSlot++;
                } else {
                    rdp_verbose("rdpdr: no free WebDAV server slots for drive \"%s\"",
                                dosName);
                }

            } else {
                rdp_verbose("rdpdr: client device #%u — id=%u name=\"%s\" type=%s (not a drive)",
                            (unsigned)i, (unsigned)devId, dosName, typeName);
            }

            /* ACK every device with RDPDR_STATUS_SUCCESS so the client knows we saw it. */
            rdpdr_send_device_reply(ctx->rdpdrChannel, devId, RDPDR_STATUS_SUCCESS);
        }

        ctx->rdpdrState = kRdpdrReady;
        rdp_info("rdpdr: device enumeration complete — handshake done");
        break;
    }

    /* ── IRP I/O Completion (client -> server) ───────────────────────────── */
    case PAKID_CORE_DEVICE_IOCOMPLETION: {
        /* MS-RDPEFS §2.2.1.5  DR_DEVICE_IOCOMPLETION
         * Header(4 already consumed) + DeviceId(4) + CompletionId(4) +
         * IoStatus(4) = 12 more bytes before the payload. */
        if (Stream_GetRemainingLength(s) < 12) {
            rdp_verbose("rdpdr: IOCOMPLETION too short (%zu bytes remaining)",
                        Stream_GetRemainingLength(s));
            break;
        }
        UINT32 devId, completionId, ioStatus;
        Stream_Read_UINT32(s, devId);
        Stream_Read_UINT32(s, completionId);
        Stream_Read_UINT32(s, ioStatus);

        /* Grab the payload bytes before we call rdpdr_free_request (which invokes
         * the callback that might use them).  The stream is stack-allocated over
         * the original read buffer, so the pointer is valid during this call. */
        const uint8_t *payload    = Stream_Pointer(s);
        uint32_t       payloadLen = (uint32_t)Stream_GetRemainingLength(s);

        /* Look up the pending request, invoke its callback, and free the slot. */
        uint32_t matchedDev = rdpdr_free_request(ctx, completionId,
                                                  ioStatus, payload, payloadLen);
        if (matchedDev == 0) {
            /* Could be an unsolicited completion for a request we didn't send
             * (e.g. the client proactively sending info). Log and ignore. */
            rdp_verbose("rdpdr: <- IOCOMPLETION dev=%u cid=%u status=0x%08x "
                        "(no matching pending request)",
                        devId, completionId, ioStatus);
            break;
        }

        rdp_verbose("rdpdr: IOCOMPLETION dev=%u cid=%u status=0x%08x payload=%u bytes",
                    devId, completionId, ioStatus, payloadLen);
        break;
    }

    default:
        rdp_verbose("rdpdr: unhandled packetId=0x%04x in state=%d", packetId, ctx->rdpdrState);
        break;
    }
}

/*
 * Open the "rdpdr" static virtual channel. Called from peer_post_connect when
 * RDP_RDPDR_ENABLED=1. Returns true if the channel opened and SERVER_ANNOUNCE
 * was sent successfully.
 */
bool rdp_peer_open_rdpdr(freerdp_peer *peer) {
    const char *env = getenv("RDP_RDPDR_ENABLED");
    if (!env || strcmp(env, "1") != 0) {
        rdp_verbose("rdpdr: disabled (RDP_RDPDR_ENABLED != 1)");
        return false;
    }

    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->vcm || ctx->vcm == INVALID_HANDLE_VALUE) {
        rdp_error("rdpdr: VCM not open");
        return false;
    }

    /* Open as a STATIC virtual channel. rdpdr is always static (not drdynvc). */
    ctx->rdpdrChannel = WTSVirtualChannelOpen(ctx->vcm,
                                               WTS_CURRENT_SESSION,
                                               (LPSTR)"rdpdr");
    if (!ctx->rdpdrChannel || ctx->rdpdrChannel == INVALID_HANDLE_VALUE) {
        ctx->rdpdrChannel = NULL;
        rdp_verbose("rdpdr: WTSVirtualChannelOpen failed — "
                    "client may not have advertised the channel");
        return false;
    }

    /* Retrieve the channel's event handle for the run-loop WaitForMultipleObjects. */
    void   *evPtr = NULL;
    ULONG   evLen = sizeof(evPtr);
    if (WTSVirtualChannelQuery(ctx->rdpdrChannel,
                               WTSVirtualEventHandle, &evPtr, &evLen) && evPtr) {
        ctx->rdpdrEvent = (HANDLE)*(void **)evPtr;
        WTSFreeMemory(evPtr);
    }

    ctx->rdpdrState    = kRdpdrIdle;
    ctx->rdpdrClientId = 0;
    ctx->rdpdrHelloTries = 0;
    ctx->rdpdrHeard = false;
    ctx->rdpdrLoggedOnSent = false;
    rdp_verbose("rdpdr: channel open; SERVER_ANNOUNCE waits for activation");
    return true;
}

/* Send (or resend) SERVER_ANNOUNCE, which starts the MS-RDPEFS handshake.
 * Called once the client is activated and then from the run loop while the
 * client hasn't answered. Caller holds xportLock. */
static void rdpdr_send_hello(RDPPeerContext *ctx) {
    if (!ctx->rdpdrChannel) return;
    if (ctx->rdpdrState != kRdpdrIdle && ctx->rdpdrState != kRdpdrSentAnnounce) return;
    if (ctx->rdpdrHelloTries >= kChannelHelloTries) return;
    ctx->rdpdrHelloTries++;
    ctx->rdpdrHelloMs = mono_ms();
    if (!rdpdr_send_server_announce(ctx->rdpdrChannel)) {
        rdp_error("rdpdr: SERVER_ANNOUNCE write failed");
        ctx->rdpdrState = kRdpdrError;
        return;
    }
    ctx->rdpdrState = kRdpdrSentAnnounce;
    if (ctx->rdpdrHelloTries == 1) rdp_info("rdpdr: SERVER_ANNOUNCE sent");
    else rdp_info("rdpdr: no reply from the client — SERVER_ANNOUNCE resent (%d/%d)",
                  ctx->rdpdrHelloTries, kChannelHelloTries);
}

static void rdpdr_retry_hello(RDPPeerContext *ctx) {
    if (ctx->rdpdrChannel && ctx->rdpdrState == kRdpdrSentAnnounce && !ctx->rdpdrHeard &&
        mono_ms() - ctx->rdpdrHelloMs >= kChannelHelloRetryMs)
        rdpdr_send_hello(ctx);
}

/* Maximum PDU size for a static virtual channel. The RDP spec limits static
 * VC PDUs to CHANNEL_CHUNK_LENGTH (1600) per write, and rdpdr PDUs are
 * small (handshake packets < 100 bytes; device list < 512 bytes). 4096
 * gives comfortable headroom for a list of many devices. */
#define RDPDR_READ_BUF_SIZE 4096

/*
 * Drain all pending inbound PDUs from the rdpdr channel and advance the
 * MS-RDPEFS handshake state machine. Called from the peer run loop under
 * xportLock whenever the rdpdr event handle fires.
 */
void rdp_peer_pump_rdpdr(freerdp_peer *peer) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->rdpdrChannel || ctx->rdpdrState == kRdpdrError) return;

    /* WTSVirtualChannelRead(handle, timeout_ms, buf, bufSize, &bytesRead).
     * timeout=0 → non-blocking; returns FALSE when no data is pending. */
    BYTE  buf[RDPDR_READ_BUF_SIZE];
    ULONG bytesRead = 0;
    while (WTSVirtualChannelRead(ctx->rdpdrChannel, 0,
                                  (PCHAR)buf, (ULONG)sizeof(buf), &bytesRead)
           && bytesRead > 0) {
        rdpdr_handle_pdu(ctx, buf, bytesRead);
        bytesRead = 0;
    }
}
