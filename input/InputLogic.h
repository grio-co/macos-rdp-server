#pragma once
/* Pure (CoreGraphics-free) input logic so it can be unit-tested with plain clang.
 * See tests/test_input_logic.c. Header-only; all functions static inline. */
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

/* ── CGEventFlags values (kept as raw constants to avoid a CG dependency) ── */
#define IL_FLAG_ALPHASHIFT 0x00010000ULL
#define IL_FLAG_SHIFT      0x00020000ULL
#define IL_FLAG_CONTROL    0x00040000ULL
#define IL_FLAG_ALTERNATE  0x00080000ULL
#define IL_FLAG_COMMAND    0x00100000ULL
/* Device-dependent (NX_DEVICE*KEYMASK) bits */
#define IL_DEV_LCTL   0x00000001ULL
#define IL_DEV_LSHIFT 0x00000002ULL
#define IL_DEV_RSHIFT 0x00000004ULL
#define IL_DEV_LCMD   0x00000008ULL
#define IL_DEV_RCMD   0x00000010ULL
#define IL_DEV_LALT   0x00000020ULL
#define IL_DEV_RALT   0x00000040ULL
#define IL_DEV_RCTL   0x00002000ULL

/* macOS virtual key codes of the modifier keys. */
#define IL_VK_CMD_L 55
#define IL_VK_CMD_R 54
#define IL_VK_SHIFT_L 56
#define IL_VK_SHIFT_R 60
#define IL_VK_ALT_L 58
#define IL_VK_ALT_R 61
#define IL_VK_CTRL_L 59
#define IL_VK_CTRL_R 62
#define IL_VK_CAPS 57

/* Device bit for a modifier VK; 0 if vk is not a (non-caps) modifier. */
static inline uint64_t il_modifier_device_bit(unsigned vk) {
    switch (vk) {
    case IL_VK_CTRL_L:  return IL_DEV_LCTL;
    case IL_VK_CTRL_R:  return IL_DEV_RCTL;
    case IL_VK_SHIFT_L: return IL_DEV_LSHIFT;
    case IL_VK_SHIFT_R: return IL_DEV_RSHIFT;
    case IL_VK_CMD_L:   return IL_DEV_LCMD;
    case IL_VK_CMD_R:   return IL_DEV_RCMD;
    case IL_VK_ALT_L:   return IL_DEV_LALT;
    case IL_VK_ALT_R:   return IL_DEV_RALT;
    default: return 0;
    }
}

/* Full CGEventFlags from held device bits + caps-lock state. */
static inline uint64_t il_event_flags(uint64_t devBits, bool caps) {
    uint64_t f = devBits;
    if (devBits & (IL_DEV_LSHIFT | IL_DEV_RSHIFT)) f |= IL_FLAG_SHIFT;
    if (devBits & (IL_DEV_LCTL | IL_DEV_RCTL))     f |= IL_FLAG_CONTROL;
    if (devBits & (IL_DEV_LALT | IL_DEV_RALT))     f |= IL_FLAG_ALTERNATE;
    if (devBits & (IL_DEV_LCMD | IL_DEV_RCMD))     f |= IL_FLAG_COMMAND;
    if (caps) f |= IL_FLAG_ALPHASHIFT;
    return f;
}

/* ── Wheel ──────────────────────────────────────────────────────────────
 * Rotation is a 9-bit two's-complement value in flags & 0x1FF (0x100 = sign):
 * 0x078 = +120, 0x188 = -120. */
static inline int il_wheel_rotation(uint16_t flags) {
    int r = flags & 0x1FF;
    if (r & 0x100) r -= 0x200;
    return r;
}

#define IL_WHEEL_DELTA 120.0
#define IL_PIXELS_PER_NOTCH 48.0

/* Accumulate rotation (RDP units) and return whole pixels to emit now; the
 * fractional remainder stays in *acc. Small precision-touchpad deltas thus add
 * up smoothly instead of each becoming a full line. */
static inline int il_wheel_accumulate(double *acc, int rotation) {
    *acc += (double)rotation * IL_PIXELS_PER_NOTCH / IL_WHEEL_DELTA;
    double whole = trunc(*acc);
    *acc -= whole;
    return (int)whole;
}

/* ── Click count ─────────────────────────────────────────────────────── */
typedef struct {
    int      button;      /* -1 none */
    double   time;        /* seconds of last down */
    int      x, y;
    int      count;
} ILClickTracker;

static inline void il_click_init(ILClickTracker *t) {
    t->button = -1; t->time = 0; t->x = t->y = 0; t->count = 0;
}

/* Register a button-down; returns its click state (1, 2, 3...). */
static inline int il_click_down(ILClickTracker *t, int button, double now,
                                double interval, int x, int y) {
    int dx = x - t->x, dy = y - t->y;
    if (t->button == button && t->count > 0 && (now - t->time) <= interval &&
        dx >= -4 && dx <= 4 && dy >= -4 && dy <= 4)
        t->count++;
    else
        t->count = 1;
    t->button = button; t->time = now; t->x = x; t->y = y;
    return t->count;
}

/* ── Multi-monitor pointer mapping ────────────────────────────────────────
 * RDP pointer coordinates are in the client's desktop space (client pixels,
 * origin at the top-left of all its monitors). Each monitor is served by its
 * own Mac display, whose global rect is in points (smaller than the monitor's
 * pixels when HiDPI). */
typedef struct { double x, y, w, h; } ILRect;

/* Monitor containing (x,y), else the nearest one (pointer in a gap between
 * monitors, or on an edge pixel the client still reports). */
static inline int il_monitor_at(const ILRect *mons, int n, double x, double y) {
    int best = 0;
    double bestD = INFINITY;
    for (int i = 0; i < n; i++) {
        const ILRect *m = &mons[i];
        double dx = x < m->x ? m->x - x : (x >= m->x + m->w ? x - (m->x + m->w) + 1 : 0);
        double dy = y < m->y ? m->y - y : (y >= m->y + m->h ? y - (m->y + m->h) + 1 : 0);
        double d = dx * dx + dy * dy;
        if (d == 0) return i;
        if (d < bestD) { bestD = d; best = i; }
    }
    return best;
}

/* Maps desktop pixel (x,y) of monitor `m` to a point inside display rect `g`,
 * using pixel centres and staying strictly inside the display (its right and
 * bottom edges belong to the neighbouring display). */
static inline void il_map_into(ILRect m, ILRect g, double x, double y,
                               double *ox, double *oy) {
    double fx = m.w > 0 ? (x - m.x + 0.5) / m.w : 0;
    double fy = m.h > 0 ? (y - m.y + 0.5) / m.h : 0;
    double px = fx * g.w, py = fy * g.h;
    if (px < 0) px = 0; else if (px > g.w - 0.01) px = g.w - 0.01;
    if (py < 0) py = 0; else if (py > g.h - 0.01) py = g.h - 0.01;
    *ox = g.x + px;
    *oy = g.y + py;
}
