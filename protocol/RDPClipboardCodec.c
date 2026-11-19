#include "protocol/RDPClipboardCodec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ── little-endian helpers ────────────────────────────────────────────────── */

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }
static inline void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static inline void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static inline void wr64(uint8_t *p, uint64_t v) { wr32(p, (uint32_t)v); wr32(p + 4, (uint32_t)(v >> 32)); }

/* ── UTF ──────────────────────────────────────────────────────────────────── */

size_t rdp_utf8_to_utf16(const char *s, uint16_t *dst, size_t cap) {
    const uint8_t *p = (const uint8_t *)s;
    size_t n = 0;
    while (*p) {
        uint32_t cp;
        int extra;
        if (*p < 0x80)              { cp = *p;        extra = 0; }
        else if ((*p & 0xE0) == 0xC0) { cp = *p & 0x1F; extra = 1; }
        else if ((*p & 0xF0) == 0xE0) { cp = *p & 0x0F; extra = 2; }
        else if ((*p & 0xF8) == 0xF0) { cp = *p & 0x07; extra = 3; }
        else return (size_t)-1;
        for (int i = 1; i <= extra; i++) {
            if ((p[i] & 0xC0) != 0x80) return (size_t)-1;
            cp = (cp << 6) | (p[i] & 0x3F);
        }
        if ((extra == 1 && cp < 0x80) || (extra == 2 && cp < 0x800) ||
            (extra == 3 && cp < 0x10000) || cp > 0x10FFFF ||
            (cp >= 0xD800 && cp <= 0xDFFF))
            return (size_t)-1;
        p += extra + 1;
        if (cp >= 0x10000) {
            if (n + 2 > cap) return (size_t)-1;
            cp -= 0x10000;
            if (dst) { dst[n] = (uint16_t)(0xD800 | (cp >> 10)); dst[n + 1] = (uint16_t)(0xDC00 | (cp & 0x3FF)); }
            n += 2;
        } else {
            if (n + 1 > cap) return (size_t)-1;
            if (dst) dst[n] = (uint16_t)cp;
            n += 1;
        }
    }
    if (dst && n + 1 <= cap) dst[n] = 0;
    else if (dst) return (size_t)-1;
    return n;
}

char *rdp_utf16_to_utf8(const uint16_t *s, size_t len) {
    char *out = (char *)malloc(len * 3 + 1);
    if (!out) return NULL;
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        uint32_t cp = s[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < len && s[i + 1] >= 0xDC00 && s[i + 1] <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (s[i + 1] - 0xDC00);
            i++;
        } else if (cp >= 0xD800 && cp <= 0xDFFF) {
            cp = 0xFFFD;   /* lone surrogate */
        }
        if (cp < 0x80)         out[o++] = (char)cp;
        else if (cp < 0x800)   { out[o++] = (char)(0xC0 | (cp >> 6)); out[o++] = (char)(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) { out[o++] = (char)(0xE0 | (cp >> 12)); out[o++] = (char)(0x80 | ((cp >> 6) & 0x3F)); out[o++] = (char)(0x80 | (cp & 0x3F)); }
        else { out[o++] = (char)(0xF0 | (cp >> 18)); out[o++] = (char)(0x80 | ((cp >> 12) & 0x3F)); out[o++] = (char)(0x80 | ((cp >> 6) & 0x3F)); out[o++] = (char)(0x80 | (cp & 0x3F)); }
    }
    out[o] = 0;
    return out;
}

/* ── CF_HTML ──────────────────────────────────────────────────────────────── */

#define HTML_HDR_LEN 105   /* "Version:0.9\r\n" + 4 fixed-width offset lines */
#define MARK_START "<!--StartFragment-->"
#define MARK_END   "<!--EndFragment-->"

/* Case-insensitive search for needle in [h, h+n). */
static const uint8_t *ci_find(const uint8_t *h, size_t n, const char *needle) {
    size_t m = strlen(needle);
    if (m == 0 || n < m) return NULL;
    for (size_t i = 0; i + m <= n; i++) {
        size_t j = 0;
        while (j < m && tolower(h[i + j]) == tolower((unsigned char)needle[j])) j++;
        if (j == m) return h + i;
    }
    return NULL;
}
static const uint8_t *ci_rfind(const uint8_t *h, size_t n, const char *needle) {
    size_t m = strlen(needle);
    if (m == 0 || n < m) return NULL;
    for (size_t i = n - m + 1; i-- > 0;) {
        size_t j = 0;
        while (j < m && tolower(h[i + j]) == tolower((unsigned char)needle[j])) j++;
        if (j == m) return h + i;
    }
    return NULL;
}

bool rdp_cf_html_build(const uint8_t *html, size_t len, uint8_t **out, size_t *outLen) {
    if (!out || !outLen || (!html && len)) return false;
    /* Decide where the fragment starts/ends inside a whole-document input. */
    size_t a = 0, b = len;        /* fragment = html[a..b) */
    bool whole = false;
    const uint8_t *body = ci_find(html, len, "<body");
    if (body) {
        const uint8_t *gt = memchr(body, '>', (size_t)(html + len - body));
        if (gt) {
            a = (size_t)(gt + 1 - html);
            const uint8_t *end = ci_rfind(html + a, len - a, "</body");
            b = end ? (size_t)(end - html) : len;
            whole = true;
        }
    }
    const char *pre  = "<html><body>\r\n";
    const char *post = "\r\n</body></html>";
    size_t preLen = whole ? 0 : strlen(pre);
    size_t postLen = whole ? 0 : strlen(post);
    size_t mS = strlen(MARK_START), mE = strlen(MARK_END);

    size_t headLen = whole ? a : len;   /* bytes before the fragment (whole) */
    size_t total;
    uint8_t *buf;
    size_t startFrag, endFrag, endHtml;
    if (whole) {
        total = HTML_HDR_LEN + a + mS + (b - a) + mE + (len - b);
        startFrag = HTML_HDR_LEN + a + mS;
        endFrag = startFrag + (b - a);
        endHtml = total;
        buf = (uint8_t *)malloc(total + 1);
        if (!buf) return false;
        size_t o = HTML_HDR_LEN;
        memcpy(buf + o, html, a);               o += a;
        memcpy(buf + o, MARK_START, mS);        o += mS;
        memcpy(buf + o, html + a, b - a);       o += b - a;
        memcpy(buf + o, MARK_END, mE);          o += mE;
        memcpy(buf + o, html + b, len - b);     o += len - b;
    } else {
        (void)headLen;
        total = HTML_HDR_LEN + preLen + mS + len + mE + postLen;
        startFrag = HTML_HDR_LEN + preLen + mS;
        endFrag = startFrag + len;
        endHtml = total;
        buf = (uint8_t *)malloc(total + 1);
        if (!buf) return false;
        size_t o = HTML_HDR_LEN;
        memcpy(buf + o, pre, preLen);           o += preLen;
        memcpy(buf + o, MARK_START, mS);        o += mS;
        if (len) memcpy(buf + o, html, len);    o += len;
        memcpy(buf + o, MARK_END, mE);          o += mE;
        memcpy(buf + o, post, postLen);         o += postLen;
    }
    char hdr[HTML_HDR_LEN + 1];                 /* snprintf's NUL must not clobber the body */
    int hl = snprintf(hdr, sizeof hdr,
                      "Version:0.9\r\nStartHTML:%010u\r\nEndHTML:%010u\r\n"
                      "StartFragment:%010u\r\nEndFragment:%010u\r\n",
                      (unsigned)HTML_HDR_LEN, (unsigned)endHtml,
                      (unsigned)startFrag, (unsigned)endFrag);
    if (hl != HTML_HDR_LEN) { free(buf); return false; }
    memcpy(buf, hdr, HTML_HDR_LEN);
    buf[total] = 0;                     /* trailing NUL, not counted in EndHTML */
    *out = buf;
    *outLen = total + 1;
    return true;
}

static bool hdr_value(const uint8_t *data, size_t len, const char *key, long *val) {
    size_t kl = strlen(key);
    size_t lim = len < 512 ? len : 512;      /* the header is short */
    for (size_t i = 0; i + kl < lim; i++) {
        if ((i == 0 || data[i - 1] == '\n') && memcmp(data + i, key, kl) == 0) {
            char tmp[24];
            size_t j = 0, k = i + kl;
            while (k < len && j < sizeof(tmp) - 1 && data[k] != '\r' && data[k] != '\n')
                tmp[j++] = (char)data[k++];
            tmp[j] = 0;
            char *end;
            long v = strtol(tmp, &end, 10);
            if (end == tmp) return false;
            *val = v;
            return true;
        }
    }
    return false;
}

bool rdp_cf_html_parse(const uint8_t *data, size_t len,
                       const uint8_t **html, size_t *htmlLen,
                       const uint8_t **frag, size_t *fragLen) {
    if (!data || !html || !htmlLen || !frag || !fragLen) return false;
    while (len > 0 && data[len - 1] == 0) len--;       /* strip NUL terminator(s) */
    if (len == 0) return false;

    long sH = -1, eH = -1, sF = -1, eF = -1;
    hdr_value(data, len, "StartHTML:", &sH);
    hdr_value(data, len, "EndHTML:", &eH);
    hdr_value(data, len, "StartFragment:", &sF);
    hdr_value(data, len, "EndFragment:", &eF);

    size_t hs, he, fs, fe;
    bool hOk = sH >= 0 && (size_t)sH < len;
    if (hOk) {
        hs = (size_t)sH;
        he = (eH > sH && (size_t)eH <= len) ? (size_t)eH : len;
    } else {
        /* No usable header: skip any leading "Key:value" lines, take the rest. */
        size_t i = 0;
        while (i < len && data[i] != '<') {
            while (i < len && data[i] != '\n') i++;
            if (i < len) i++;
        }
        hs = i; he = len;
        if (hs >= he) return false;
    }
    bool fOk = sF >= (long)hs && eF > sF && (size_t)eF <= he;
    if (fOk) {
        fs = (size_t)sF; fe = (size_t)eF;
    } else {
        const uint8_t *ms = ci_find(data + hs, he - hs, MARK_START);
        const uint8_t *me = ci_find(data + hs, he - hs, MARK_END);
        if (ms && me && me > ms) {
            fs = (size_t)(ms - data) + strlen(MARK_START);
            fe = (size_t)(me - data);
        } else { fs = hs; fe = he; }
    }
    *html = data + hs; *htmlLen = he - hs;
    *frag = data + fs; *fragLen = fe - fs;
    return true;
}

/* ── DIB ──────────────────────────────────────────────────────────────────── */

#define BI_RGB            0
#define BI_RLE8           1
#define BI_RLE4           2
#define BI_BITFIELDS      3
#define BI_ALPHABITFIELDS 6

typedef struct { uint32_t mask; int shift; int bits; } Chan;

static Chan chan_from_mask(uint32_t m) {
    Chan c = { m, 0, 0 };
    if (!m) return c;
    while (!((m >> c.shift) & 1)) c.shift++;
    uint32_t t = m >> c.shift;
    while (t & 1) { c.bits++; t >>= 1; }
    return c;
}
static inline uint8_t chan_get(Chan c, uint32_t px) {
    if (!c.mask) return 0;
    uint32_t v = (px & c.mask) >> c.shift;
    if (c.bits >= 8) return (uint8_t)(v >> (c.bits - 8));
    return (uint8_t)((v * 255u + ((1u << c.bits) - 1) / 2) / ((1u << c.bits) - 1));
}

bool rdp_dib_decode(const uint8_t *d, size_t n, RDPBitmap *out) {
    if (!d || !out || n < 40) return false;
    memset(out, 0, sizeof(*out));
    uint32_t hsz = rd32(d);
    if (hsz != 40 && hsz != 52 && hsz != 56 && hsz != 108 && hsz != 124) return false;
    if (n < hsz) return false;
    int32_t w = (int32_t)rd32(d + 4), h = (int32_t)rd32(d + 8);
    uint16_t planes = rd16(d + 12), bpp = rd16(d + 14);
    uint32_t comp = rd32(d + 16), clrUsed = rd32(d + 32);
    if (planes != 1 || w <= 0 || h == 0 || w > 32767) return false;
    bool topDown = h < 0;
    uint32_t absH = (uint32_t)(topDown ? -(int64_t)h : h);
    if (absH > 32767) return false;
    if (comp != BI_RGB && comp != BI_BITFIELDS && comp != BI_ALPHABITFIELDS) return false;
    if (bpp != 1 && bpp != 4 && bpp != 8 && bpp != 16 && bpp != 24 && bpp != 32) return false;

    uint32_t mR = 0, mG = 0, mB = 0, mA = 0;
    size_t off = hsz;
    if (hsz >= 52) {                        /* V2+ headers carry the masks */
        if (comp == BI_BITFIELDS || comp == BI_ALPHABITFIELDS) {
            mR = rd32(d + 40); mG = rd32(d + 44); mB = rd32(d + 48);
            if (hsz >= 56) mA = rd32(d + 52);
        }
    } else if (comp == BI_BITFIELDS || comp == BI_ALPHABITFIELDS) {
        size_t cnt = comp == BI_ALPHABITFIELDS ? 4 : 3;
        if (n < off + cnt * 4) return false;
        mR = rd32(d + off); mG = rd32(d + off + 4); mB = rd32(d + off + 8);
        if (cnt == 4) mA = rd32(d + off + 12);
        off += cnt * 4;
    }
    if ((comp == BI_BITFIELDS || comp == BI_ALPHABITFIELDS) && bpp != 16 && bpp != 32) return false;
    if (comp == BI_RGB || !(mR | mG | mB)) {
        if (bpp == 16)      { mR = 0x7C00; mG = 0x03E0; mB = 0x001F; mA = 0; }
        else if (bpp == 32) { mR = 0x00FF0000; mG = 0x0000FF00; mB = 0x000000FF; /* A: heuristic */ }
    }

    uint32_t pal[256];
    uint32_t palN = 0;
    if (bpp <= 8) {
        palN = clrUsed ? clrUsed : (1u << bpp);
        if (palN > 256 || palN > (1u << bpp)) return false;
        if (n < off + (size_t)palN * 4) return false;
        for (uint32_t i = 0; i < palN; i++) pal[i] = rd32(d + off + i * 4);
        off += (size_t)palN * 4;
    }

    size_t stride = (((size_t)w * bpp + 31) / 32) * 4;
    if (stride * absH > n - off) return false;        /* truncated pixel data */
    size_t outSize = (size_t)w * absH * 4;
    uint8_t *px = (uint8_t *)malloc(outSize ? outSize : 1);
    if (!px) return false;

    Chan cR = chan_from_mask(mR), cG = chan_from_mask(mG), cB = chan_from_mask(mB), cA = chan_from_mask(mA);
    bool alphaSeen = false;
    const bool heurAlpha = (bpp == 32 && comp == BI_RGB);   /* alpha byte of plain BI_RGB */
    for (uint32_t y = 0; y < absH; y++) {
        const uint8_t *src = d + off + (size_t)(topDown ? y : absH - 1 - y) * stride;
        uint8_t *dst = px + (size_t)y * w * 4;
        for (int32_t x = 0; x < w; x++, dst += 4) {
            uint8_t r, g, b, a = 255;
            switch (bpp) {
            case 1: { uint32_t i = (src[x >> 3] >> (7 - (x & 7))) & 1; uint32_t c = i < palN ? pal[i] : 0;
                      b = c & 255; g = (c >> 8) & 255; r = (c >> 16) & 255; break; }
            case 4: { uint32_t i = (src[x >> 1] >> ((x & 1) ? 0 : 4)) & 15; uint32_t c = i < palN ? pal[i] : 0;
                      b = c & 255; g = (c >> 8) & 255; r = (c >> 16) & 255; break; }
            case 8: { uint32_t i = src[x]; uint32_t c = i < palN ? pal[i] : 0;
                      b = c & 255; g = (c >> 8) & 255; r = (c >> 16) & 255; break; }
            case 16: { uint32_t v = rd16(src + x * 2); r = chan_get(cR, v); g = chan_get(cG, v); b = chan_get(cB, v);
                       if (mA) a = chan_get(cA, v); break; }
            case 24: b = src[x * 3]; g = src[x * 3 + 1]; r = src[x * 3 + 2]; break;
            default: { uint32_t v = rd32(src + x * 4); r = chan_get(cR, v); g = chan_get(cG, v); b = chan_get(cB, v);
                       if (mA) a = chan_get(cA, v);
                       else if (heurAlpha) a = (uint8_t)(v >> 24);
                       break; }
            }
            if (a) alphaSeen = true;
            dst[0] = b; dst[1] = g; dst[2] = r; dst[3] = a;
        }
    }
    bool hasAlphaChannel = (bpp == 32 || (bpp == 16 && mA)) && (mA || heurAlpha);
    if (hasAlphaChannel && !alphaSeen) {
        /* All-zero alpha means "alpha unused" (typical of BI_RGB screenshots). */
        for (size_t i = 3; i < outSize; i += 4) px[i] = 255;
        hasAlphaChannel = false;
    } else if (hasAlphaChannel) {
        bool allOpaque = true;
        for (size_t i = 3; i < outSize; i += 4) if (px[i] != 255) { allOpaque = false; break; }
        if (allOpaque) hasAlphaChannel = false;
    }
    out->width = (uint32_t)w; out->height = absH; out->bgra = px; out->hasAlpha = hasAlphaChannel;
    return true;
}

bool rdp_dib_encode(const uint8_t *bgra, uint32_t w, uint32_t h, bool v5,
                    uint8_t **out, size_t *outLen) {
    if (!bgra || !out || !outLen || w == 0 || h == 0 || w > 32767 || h > 32767) return false;
    size_t hsz = v5 ? 124 : 40;
    size_t pixBytes = (size_t)w * h * 4;
    uint8_t *buf = (uint8_t *)calloc(1, hsz + pixBytes);
    if (!buf) return false;
    wr32(buf, (uint32_t)hsz);
    wr32(buf + 4, w);
    wr32(buf + 8, h);                         /* positive: bottom-up */
    wr16(buf + 12, 1);
    wr16(buf + 14, 32);
    wr32(buf + 16, v5 ? BI_BITFIELDS : BI_RGB);
    wr32(buf + 20, (uint32_t)pixBytes);
    if (v5) {
        wr32(buf + 40, 0x00FF0000); wr32(buf + 44, 0x0000FF00);
        wr32(buf + 48, 0x000000FF); wr32(buf + 52, 0xFF000000);
        wr32(buf + 56, 0x73524742);           /* LCS_sRGB */
        wr32(buf + 108, 4);                   /* LCS_GM_IMAGES */
    }
    uint8_t *dst = buf + hsz;
    for (uint32_t y = 0; y < h; y++) {
        const uint8_t *src = bgra + (size_t)(h - 1 - y) * w * 4;
        if (v5) {
            memcpy(dst, src, (size_t)w * 4);
        } else {
            for (uint32_t x = 0; x < w; x++) {
                uint32_t a = src[x * 4 + 3];
                if (a == 255) { memcpy(dst + x * 4, src + x * 4, 4); continue; }
                for (int c = 0; c < 3; c++)   /* composite over white */
                    dst[x * 4 + c] = (uint8_t)((src[x * 4 + c] * a + 255 * (255 - a) + 127) / 255);
                dst[x * 4 + 3] = 255;
            }
        }
        dst += (size_t)w * 4;
    }
    *out = buf;
    *outLen = hsz + pixBytes;
    return true;
}

/* ── FILEDESCRIPTORW ──────────────────────────────────────────────────────── */

#define FILETIME_UNIX_EPOCH 116444736000000000ULL   /* 1601 -> 1970 in 100 ns */

uint64_t rdp_filetime_from_unix(int64_t sec, long nsec) {
    if (sec < -11644473600LL) return 0;
    return (uint64_t)(sec + 11644473600LL) * 10000000ULL + (uint64_t)(nsec / 100);
}
bool rdp_filetime_to_unix(uint64_t ft, int64_t *sec, long *nsec) {
    if (ft < FILETIME_UNIX_EPOCH) { *sec = 0; *nsec = 0; return false; }
    uint64_t t = ft - FILETIME_UNIX_EPOCH;
    *sec = (int64_t)(t / 10000000ULL);
    *nsec = (long)((t % 10000000ULL) * 100);
    return true;
}

bool rdp_filelist_serialize(const RDPFileDesc *d, uint32_t n, uint8_t **out, size_t *outLen) {
    if (!out || !outLen || (n && !d)) return false;
    size_t total = 4 + (size_t)n * RDP_FILEDESC_WIRE_SIZE;
    uint8_t *buf = (uint8_t *)calloc(1, total);
    if (!buf) return false;
    wr32(buf, n);
    for (uint32_t i = 0; i < n; i++) {
        uint8_t *p = buf + 4 + (size_t)i * RDP_FILEDESC_WIRE_SIZE;
        wr32(p, d[i].flags);
        /* clsid(16) sizel(8) pointl(8): zero */
        wr32(p + 36, d[i].attrs);
        wr64(p + 40, d[i].creationTime);
        wr64(p + 48, d[i].accessTime);
        wr64(p + 56, d[i].writeTime);
        wr32(p + 64, (uint32_t)(d[i].size >> 32));
        wr32(p + 68, (uint32_t)d[i].size);
        uint16_t name[RDP_FD_NAME_MAX_UNITS + 1];
        size_t units = d[i].name ? rdp_utf8_to_utf16(d[i].name, name, RDP_FD_NAME_MAX_UNITS + 1) : (size_t)-1;
        if (units == (size_t)-1 || units == 0 || units > RDP_FD_NAME_MAX_UNITS) { free(buf); return false; }
        for (size_t k = 0; k <= units; k++) wr16(p + 72 + k * 2, name[k]);
    }
    *out = buf;
    *outLen = total;
    return true;
}

void rdp_filelist_free(RDPFileDesc *d, uint32_t n) {
    if (!d) return;
    for (uint32_t i = 0; i < n; i++) free(d[i].name);
    free(d);
}

bool rdp_filelist_parse(const uint8_t *data, size_t len, RDPFileDesc **out, uint32_t *n) {
    if (!data || !out || !n || len < 4) return false;
    uint32_t cnt = rd32(data);
    if (cnt > (len - 4) / RDP_FILEDESC_WIRE_SIZE) return false;
    RDPFileDesc *d = (RDPFileDesc *)calloc(cnt ? cnt : 1, sizeof(RDPFileDesc));
    if (!d) return false;
    for (uint32_t i = 0; i < cnt; i++) {
        const uint8_t *p = data + 4 + (size_t)i * RDP_FILEDESC_WIRE_SIZE;
        d[i].flags = rd32(p);
        d[i].attrs = rd32(p + 36);
        d[i].creationTime = rd64(p + 40);
        d[i].accessTime = rd64(p + 48);
        d[i].writeTime = rd64(p + 56);
        d[i].size = ((uint64_t)rd32(p + 64) << 32) | rd32(p + 68);
        uint16_t name[260];
        size_t units = 0;
        while (units < 260) { name[units] = rd16(p + 72 + units * 2); if (!name[units]) break; units++; }
        if (units == 260) units = 259;
        d[i].name = rdp_utf16_to_utf8(name, units);
        if (!d[i].name) { rdp_filelist_free(d, cnt); return false; }
    }
    *out = d;
    *n = cnt;
    return true;
}
