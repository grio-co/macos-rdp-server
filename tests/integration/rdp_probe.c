/*
 * rdp_probe — headless RDP client that exercises the server's display protocol:
 * GFX ResetGraphics / CreateSurface / MapSurfaceToOutput, the DISP caps, and two
 * live layout changes (a resize, then a two-monitor layout).
 *
 *   rdp_probe [--expect-monitors N] -- <FreeRDP client args, e.g. /v:127.0.0.1:33899 ...>
 *
 * Exit status 0 when every step was observed. Built against Homebrew FreeRDP's
 * client libraries by tests/integration/build-probe.sh; driven by
 * tests/integration/run-display-test.sh.
 */
#include <freerdp/freerdp.h>
#include <freerdp/client.h>
#include <freerdp/client/cmdline.h>
#include <freerdp/client/disp.h>
#include <freerdp/client/rdpgfx.h>
#include <freerdp/channels/disp.h>
#include <freerdp/channels/rdpgfx.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/event.h>
#include <winpr/synch.h>
#include <winpr/sysinfo.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct { rdpClientContext common; } ProbeContext;

static RdpgfxClientContext *g_gfx;
static DispClientContext   *g_disp;
static pcRdpgfxResetGraphics      o_reset;
static pcRdpgfxCreateSurface      o_create;
static pcRdpgfxMapSurfaceToOutput o_map;
static pcRdpgfxSurfaceCommand     o_cmd;

static int      g_resets, g_creates, g_maps, g_caps;
static uint64_t g_cmds;
static UINT32   g_w, g_h, g_mons, g_capsMax;

static UINT w_reset(RdpgfxClientContext *c, const RDPGFX_RESET_GRAPHICS_PDU *p) {
    g_resets++; g_w = p->width; g_h = p->height; g_mons = p->monitorCount;
    printf("  ResetGraphics #%d: %ux%u, %u monitor(s)\n", g_resets, p->width, p->height,
           p->monitorCount);
    for (UINT32 i = 0; i < p->monitorCount; i++) {
        const MONITOR_DEF *m = &p->monitorDefArray[i];
        printf("    monitor %u: (%d,%d)-(%d,%d)%s\n", i, m->left, m->top, m->right,
               m->bottom, (m->flags & 1) ? " primary" : "");
    }
    return o_reset(c, p);
}
static UINT w_create(RdpgfxClientContext *c, const RDPGFX_CREATE_SURFACE_PDU *p) {
    g_creates++;
    printf("  CreateSurface %u: %ux%u\n", p->surfaceId, p->width, p->height);
    return o_create(c, p);
}
static UINT w_map(RdpgfxClientContext *c, const RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU *p) {
    g_maps++;
    printf("  MapSurfaceToOutput %u at (%u,%u)\n", p->surfaceId, p->outputOriginX,
           p->outputOriginY);
    return o_map(c, p);
}
/* Slow-client simulation: the client decodes/acks one frame per g_slowMs (the
 * FrameAcknowledge goes out after this callback returns), and once stalls for
 * g_stallMs after frame 30 (acks stop completely for that long). */
static UINT32 g_slowMs, g_stallMs;
static UINT w_cmd(RdpgfxClientContext *c, const RDPGFX_SURFACE_COMMAND *p) {
    g_cmds++;
    if (g_stallMs && g_cmds == 30) {
        printf("  stall: no acks for %u ms\n", g_stallMs);
        fflush(stdout);
        Sleep(g_stallMs);
    } else if (g_slowMs) {
        Sleep(g_slowMs);
    }
    return o_cmd(c, p);
}
static UINT w_caps(DispClientContext *d, UINT32 maxMon, UINT32 a, UINT32 b) {
    (void)d;
    g_caps = 1; g_capsMax = maxMon;
    printf("  DISP caps: MaxNumMonitors=%u area=%ux%u\n", maxMon, a, b);
    return CHANNEL_RC_OK;
}

static void on_channel_connected(void *context, const ChannelConnectedEventArgs *e) {
    if (strcmp(e->name, DISP_DVC_CHANNEL_NAME) == 0) {
        g_disp = (DispClientContext *)e->pInterface;
        g_disp->DisplayControlCaps = w_caps;
        return;
    }
    freerdp_client_OnChannelConnectedEventHandler(context, e);
    if (strcmp(e->name, RDPGFX_DVC_CHANNEL_NAME) == 0) {
        g_gfx = (RdpgfxClientContext *)e->pInterface;
        o_reset = g_gfx->ResetGraphics;        g_gfx->ResetGraphics = w_reset;
        o_create = g_gfx->CreateSurface;       g_gfx->CreateSurface = w_create;
        o_map = g_gfx->MapSurfaceToOutput;     g_gfx->MapSurfaceToOutput = w_map;
        o_cmd = g_gfx->SurfaceCommand;         g_gfx->SurfaceCommand = w_cmd;
    }
}
static void on_channel_disconnected(void *context, const ChannelDisconnectedEventArgs *e) {
    if (strcmp(e->name, DISP_DVC_CHANNEL_NAME) == 0) { g_disp = NULL; return; }
    if (strcmp(e->name, RDPGFX_DVC_CHANNEL_NAME) == 0) g_gfx = NULL;
    freerdp_client_OnChannelDisconnectedEventHandler(context, e);
}

static BOOL probe_pre_connect(freerdp *instance) {
    PubSub_SubscribeChannelConnected(instance->context->pubSub, on_channel_connected);
    PubSub_SubscribeChannelDisconnected(instance->context->pubSub, on_channel_disconnected);
    return TRUE;
}
/* gdi_ResetGraphics resizes the client desktop through update->DesktopResize. */
static BOOL probe_desktop_resize(rdpContext *context) {
    rdpSettings *s = context->settings;
    return gdi_resize(context->gdi, freerdp_settings_get_uint32(s, FreeRDP_DesktopWidth),
                      freerdp_settings_get_uint32(s, FreeRDP_DesktopHeight));
}
static BOOL probe_post_connect(freerdp *instance) {
    if (!gdi_init(instance, PIXEL_FORMAT_BGRX32)) return FALSE;
    instance->context->update->DesktopResize = probe_desktop_resize;
    return TRUE;
}
static void probe_post_disconnect(freerdp *instance) { gdi_free(instance); }

static BOOL probe_client_new(freerdp *instance, rdpContext *context) {
    (void)context;
    instance->PreConnect     = probe_pre_connect;
    instance->PostConnect    = probe_post_connect;
    instance->PostDisconnect = probe_post_disconnect;
    return TRUE;
}

static bool send_layout(const DISPLAY_CONTROL_MONITOR_LAYOUT *m, UINT32 n) {
    if (!g_disp || !g_disp->SendMonitorLayout) return false;
    DISPLAY_CONTROL_MONITOR_LAYOUT copy[4];
    memcpy(copy, m, n * sizeof(*m));
    return g_disp->SendMonitorLayout(g_disp, n, copy) == CHANNEL_RC_OK;
}

static int fail(const char *what) { printf("FAIL: %s\n", what); return 1; }

int main(int argc, char **argv) {
    UINT32 expectMonitors = 2;
    int sep = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--expect-monitors") == 0 && i + 1 < argc) expectMonitors = (UINT32)atoi(argv[++i]);
        else if (strcmp(argv[i], "--slow-ms") == 0 && i + 1 < argc) g_slowMs = (UINT32)atoi(argv[++i]);
        else if (strcmp(argv[i], "--stall-ms") == 0 && i + 1 < argc) g_stallMs = (UINT32)atoi(argv[++i]);
        else if (strcmp(argv[i], "--") == 0) { sep = i; break; }
    }
    if (sep < 0) { fprintf(stderr, "usage: %s [--expect-monitors N] -- <client args>\n", argv[0]); return 2; }

    RDP_CLIENT_ENTRY_POINTS ep = { 0 };
    ep.Version = RDP_CLIENT_INTERFACE_VERSION;
    ep.Size = sizeof(ep);
    ep.ContextSize = sizeof(ProbeContext);
    ep.ClientNew = probe_client_new;
    rdpContext *ctx = freerdp_client_context_new(&ep);
    if (!ctx) return fail("context");

    char **cargv = &argv[sep];          /* cargv[0] = "--" stands in for argv[0] */
    int cargc = argc - sep;
    if (freerdp_client_settings_parse_command_line(ctx->settings, cargc, cargv, FALSE) < 0)
        return fail("client arguments");
    rdpSettings *s = ctx->settings;
    freerdp_settings_set_bool(s, FreeRDP_SupportGraphicsPipeline, TRUE);
    freerdp_settings_set_bool(s, FreeRDP_GfxH264, TRUE);
    freerdp_settings_set_bool(s, FreeRDP_SupportDisplayControl, TRUE);
    freerdp_settings_set_bool(s, FreeRDP_DynamicResolutionUpdate, TRUE);

    if (!freerdp_connect(ctx->instance)) return fail("connect");
    printf("connected\n");

    static const DISPLAY_CONTROL_MONITOR_LAYOUT one[] = {
        { DISPLAY_CONTROL_MONITOR_PRIMARY, 0, 0, 1600, 900, 0, 0, 0, 100, 100 },
    };
    static const DISPLAY_CONTROL_MONITOR_LAYOUT hidpi[] = {
        { DISPLAY_CONTROL_MONITOR_PRIMARY, 0, 0, 2560, 1600, 0, 0, 0, 200, 100 },
    };
    static const DISPLAY_CONTROL_MONITOR_LAYOUT two[] = {
        { DISPLAY_CONTROL_MONITOR_PRIMARY, 0, 0, 1280, 720, 0, 0, 0, 100, 100 },
        { 0, 1280, 0, 1024, 768, 0, 0, 0, 100, 100 },
    };

    int rc = 0, step = 0;
    uint64_t t0 = GetTickCount64(), stepT = t0, cmdsAtStep = 0;
    while (!freerdp_shall_disconnect_context(ctx) && step < 4) {
        HANDLE h[MAXIMUM_WAIT_OBJECTS];
        DWORD n = freerdp_get_event_handles(ctx, h, ARRAYSIZE(h));
        if (n == 0) { rc = fail("event handles"); break; }
        WaitForMultipleObjects(n, h, FALSE, 100);
        if (!freerdp_check_event_handles(ctx)) { rc = fail("connection dropped"); break; }
        uint64_t now = GetTickCount64();
        if (step == 0) {
            if (g_resets >= 1 && g_caps && now - stepT > 2000) {
                printf("step 1: initial output %ux%u, %d surface(s), %llu frame(s)\n",
                       g_w, g_h, g_creates, (unsigned long long)g_cmds);
                printf("step 2: request 1600x900\n");
                if (!send_layout(one, 1)) { rc = fail("send layout"); break; }
                step = 1; stepT = now; cmdsAtStep = g_cmds;
            } else if (now - t0 > 15000) {
                rc = fail(g_resets ? "no DISP caps from server" : "no ResetGraphics from server");
                break;
            }
        } else if (step == 1) {
            if (g_resets >= 2 && g_w == 1600 && g_h == 900 && now - stepT > 2500) {
                printf("  resized: %llu frame(s) since\n", (unsigned long long)(g_cmds - cmdsAtStep));
                printf("step 3: request two monitors 1280x720 + 1024x768\n");
                if (!send_layout(two, 2)) { rc = fail("send layout"); break; }
                step = 2; stepT = now; cmdsAtStep = g_cmds;
            } else if (now - stepT > 12000) { rc = fail("resize to 1600x900 not applied"); break; }
        } else if (step == 2) {
            if (g_resets >= 3 && now - stepT > 2500) {
                printf("  now %ux%u with %u monitor(s): %llu frame(s) since\n", g_w, g_h, g_mons,
                       (unsigned long long)(g_cmds - cmdsAtStep));
                if (g_mons != expectMonitors) { rc = fail("unexpected monitor count"); break; }
                printf("step 4: request 2560x1600 at 200%% scale\n");
                if (!send_layout(hidpi, 1)) { rc = fail("send layout"); break; }
                step = 3; stepT = now; cmdsAtStep = g_cmds;
            } else if (now - stepT > 15000) { rc = fail("two-monitor layout not applied"); break; }
        } else if (step == 3) {
            if (g_resets >= 4 && g_w == 2560 && g_h == 1600 && now - stepT > 2500) {
                printf("  scaled: %llu frame(s) since\n", (unsigned long long)(g_cmds - cmdsAtStep));
                step = 4;
            } else if (now - stepT > 15000) { rc = fail("2560x1600 layout not applied"); break; }
        }
    }
    if (step < 4 && rc == 0) rc = fail("disconnected early");
    freerdp_disconnect(ctx->instance);
    freerdp_client_context_free(ctx);
    printf("%s (resets=%d surfaces=%d maps=%d frames=%llu)\n", rc ? "RESULT: FAIL" : "RESULT: PASS",
           g_resets, g_creates, g_maps, (unsigned long long)g_cmds);
    return rc;
}
