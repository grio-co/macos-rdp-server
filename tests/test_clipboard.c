/*
 * Unit tests for the pure clipboard pieces (no FreeRDP, no daemon, no pasteboard):
 *   CF_HTML build/parse, DIB <-> BGRA <-> PNG/TIFF, FILEDESCRIPTORW lists,
 *   file sets (nested folders, >4 GB sizes), chunked range reads and the
 *   Windows->Mac chunked folder download.
 * Run via tests/run.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>

#include "protocol/RDPClipboardCodec.h"
#include "protocol/RDPClipboardFiles.h"
#include "protocol/RDPClipboardImage.h"

static int g_fail = 0, g_pass = 0;
#define CHECK(cond) do { if (cond) g_pass++; else { g_fail++; \
    printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define SECTION(name) printf("== %s\n", name)

static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }

/* ── UTF ──────────────────────────────────────────────────────────────────── */
static void test_utf(void) {
    SECTION("UTF-8 <-> UTF-16");
    uint16_t u[64];
    size_t n = rdp_utf8_to_utf16("a\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80", u, 64);   /* a é € 😀 */
    CHECK(n == 5);
    CHECK(u[0] == 'a' && u[1] == 0xE9 && u[2] == 0x20AC && u[3] == 0xD83D && u[4] == 0xDE00 && u[5] == 0);
    char *back = rdp_utf16_to_utf8(u, n);
    CHECK(back && strcmp(back, "a\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80") == 0);
    free(back);
    CHECK(rdp_utf8_to_utf16("\xC0\x80", u, 64) == (size_t)-1);          /* overlong */
    CHECK(rdp_utf8_to_utf16("\xED\xA0\x80", u, 64) == (size_t)-1);      /* surrogate */
    CHECK(rdp_utf8_to_utf16("abcdef", u, 4) == (size_t)-1);             /* too long */
}

/* ── CF_HTML ──────────────────────────────────────────────────────────────── */
static long hdr_num(const uint8_t *d, const char *key) {
    const char *p = strstr((const char *)d, key);
    return p ? strtol(p + strlen(key), NULL, 10) : -999;
}
static void test_html(void) {
    SECTION("CF_HTML");
    const char *frag = "<b>h\xC3\xA9llo</b> \xE2\x82\xAC";
    uint8_t *out; size_t n;
    CHECK(rdp_cf_html_build((const uint8_t *)frag, strlen(frag), &out, &n));
    CHECK(strncmp((char *)out, "Version:0.9\r\nStartHTML:0000000105\r\n", 34) == 0);
    long sH = hdr_num(out, "StartHTML:"), eH = hdr_num(out, "EndHTML:");
    long sF = hdr_num(out, "StartFragment:"), eF = hdr_num(out, "EndFragment:");
    CHECK(sH == 105);
    CHECK(eH == (long)n - 1);                                   /* EndHTML excludes the NUL */
    CHECK(out[n - 1] == 0);
    CHECK((size_t)(eF - sF) == strlen(frag) && memcmp(out + sF, frag, strlen(frag)) == 0);
    CHECK(memcmp(out + sF - 20, "<!--StartFragment-->", 20) == 0);
    CHECK(memcmp(out + eF, "<!--EndFragment-->", 18) == 0);
    CHECK(memcmp(out + sH, "<html>", 6) == 0);
    const uint8_t *h, *f; size_t hl, fl;
    CHECK(rdp_cf_html_parse(out, n, &h, &hl, &f, &fl));
    CHECK(fl == strlen(frag) && memcmp(f, frag, fl) == 0);
    CHECK(hl == (size_t)(eH - sH) && memcmp(h, "<html><body>", 12) == 0);
    free(out);

    /* whole document: head preserved, markers go inside <body> */
    const char *doc = "<!DOCTYPE html><html><head><style>p{color:red}</style></head><BODY class=x><p>hi</p></BODY></html>";
    CHECK(rdp_cf_html_build((const uint8_t *)doc, strlen(doc), &out, &n));
    sF = hdr_num(out, "StartFragment:"); eF = hdr_num(out, "EndFragment:");
    CHECK(rdp_cf_html_parse(out, n, &h, &hl, &f, &fl));
    CHECK(fl == 9 && memcmp(f, "<p>hi</p>", 9) == 0);
    CHECK(strstr((char *)out, "<style>p{color:red}</style>") != NULL);
    CHECK(memcmp(out + sF - 20, "<!--StartFragment-->", 20) == 0);
    CHECK(memcmp(out + eF, "<!--EndFragment-->", 18) == 0);
    free(out);

    /* parse a Windows-style payload with CRLF header and non-trivial offsets */
    char win[512];
    const char *body = "<html>\r\n<body>\r\n<!--StartFragment--><i>x</i><!--EndFragment-->\r\n</body>\r\n</html>";
    int hdrlen = 97;   /* with the %010d layout of the test below */
    char tmp[256];
    snprintf(tmp, sizeof tmp, "Version:1.0\r\nStartHTML:%010d\r\nEndHTML:%010d\r\nStartFragment:%010d\r\nEndFragment:%010d\r\n",
             0, 0, 0, 0);
    hdrlen = (int)strlen(tmp);
    int sf = hdrlen + (int)(strstr(body, "<i>") - body), ef = hdrlen + (int)(strstr(body, "<!--EndF") - body);
    int len = snprintf(win, sizeof win, "Version:1.0\r\nStartHTML:%010d\r\nEndHTML:%010d\r\nStartFragment:%010d\r\nEndFragment:%010d\r\n%s",
                       hdrlen, hdrlen + (int)strlen(body), sf, ef, body);
    CHECK(rdp_cf_html_parse((uint8_t *)win, (size_t)len + 1, &h, &hl, &f, &fl));   /* +1: trailing NUL */
    CHECK(fl == 8 && memcmp(f, "<i>x</i>", 8) == 0);
    CHECK(hl == strlen(body));

    /* no / garbage header: falls back to markers, then to the payload */
    const char *nohdr = "<html><!--StartFragment-->abc<!--EndFragment--></html>";
    CHECK(rdp_cf_html_parse((const uint8_t *)nohdr, strlen(nohdr), &h, &hl, &f, &fl));
    CHECK(fl == 3 && memcmp(f, "abc", 3) == 0);
    const char *plain = "Version:0.9\r\nStartHTML:abc\r\n<p>zz</p>";
    CHECK(rdp_cf_html_parse((const uint8_t *)plain, strlen(plain), &h, &hl, &f, &fl));
    CHECK(hl == 9 && memcmp(h, "<p>zz</p>", 9) == 0);
    CHECK(!rdp_cf_html_parse((const uint8_t *)"", 0, &h, &hl, &f, &fl));

    /* empty fragment still builds a valid document */
    CHECK(rdp_cf_html_build((const uint8_t *)"", 0, &out, &n));
    CHECK(rdp_cf_html_parse(out, n, &h, &hl, &f, &fl) && fl == 0);
    free(out);
}

/* ── DIB ──────────────────────────────────────────────────────────────────── */
static uint8_t *make_bgra(uint32_t w, uint32_t h, int alpha) {
    uint8_t *p = malloc((size_t)w * h * 4);
    uint32_t s = 12345;
    for (size_t i = 0; i < (size_t)w * h; i++) {
        s = s * 1664525u + 1013904223u;
        p[i * 4 + 0] = (uint8_t)(s >> 8); p[i * 4 + 1] = (uint8_t)(s >> 16); p[i * 4 + 2] = (uint8_t)(s >> 24);
        p[i * 4 + 3] = alpha ? (uint8_t)(i % 7 == 0 ? 0 : 255 - (i % 5) * 40) : 255;
    }
    return p;
}

static void test_dib(void) {
    SECTION("DIB encode/decode");
    uint32_t w = 5, h = 3;
    uint8_t *src = make_bgra(w, h, 0);
    uint8_t *dib; size_t dn;
    CHECK(rdp_dib_encode(src, w, h, false, &dib, &dn));
    CHECK(dn == 40 + (size_t)w * h * 4);
    CHECK(dib[0] == 40 && (int32_t)(dib[8] | dib[9] << 8) == 3);   /* biSize, positive height = bottom-up */
    /* bottom-up: first stored row is the LAST image row */
    CHECK(memcmp(dib + 40, src + (size_t)(h - 1) * w * 4, (size_t)w * 4) == 0);
    RDPBitmap bm;
    CHECK(rdp_dib_decode(dib, dn, &bm));
    CHECK(bm.width == w && bm.height == h && !bm.hasAlpha && memcmp(bm.bgra, src, (size_t)w * h * 4) == 0);
    free(bm.bgra); free(dib);

    /* V5 with alpha round-trips exactly (straight alpha) */
    uint8_t *asrc = make_bgra(w, h, 1);
    CHECK(rdp_dib_encode(asrc, w, h, true, &dib, &dn));
    CHECK(dn == 124 + (size_t)w * h * 4 && dib[0] == 124 && dib[16] == 3);   /* BI_BITFIELDS */
    CHECK(dib[52 + 3] == 0xFF && dib[56] == 'B' && dib[57] == 'G' && dib[58] == 'R' && dib[59] == 's');
    CHECK(rdp_dib_decode(dib, dn, &bm));
    CHECK(bm.hasAlpha && memcmp(bm.bgra, asrc, (size_t)w * h * 4) == 0);
    free(bm.bgra); free(dib);
    /* plain CF_DIB flattens alpha over white */
    CHECK(rdp_dib_encode(asrc, w, h, false, &dib, &dn));
    CHECK(rdp_dib_decode(dib, dn, &bm));
    CHECK(!bm.hasAlpha);
    int flat = 1;
    for (size_t i = 0; i < (size_t)w * h; i++) {
        uint8_t a = asrc[i * 4 + 3];
        uint8_t *s = asrc + i * 4;
        for (int c = 0; c < 3; c++) {
            int e = (s[c] * a + 255 * (255 - a) + 127) / 255;
            if (abs(e - bm.bgra[i * 4 + c]) > 1) flat = 0;
        }
    }
    CHECK(flat);
    free(bm.bgra); free(dib); free(asrc); free(src);

    /* hand-built: 24 bpp bottom-up, width 3 => 12-byte stride (3 pad bytes), 2 rows */
    SECTION("DIB decode variants");
    {
        uint8_t d[40 + 24] = {0};
        put32(d, 40); put32(d + 4, 3); put32(d + 8, 2); put16(d + 12, 1); put16(d + 14, 24);
        /* stored row 0 = image bottom row */
        uint8_t row0[9] = { 1,2,3, 4,5,6, 7,8,9 }, row1[9] = { 11,12,13, 14,15,16, 17,18,19 };
        memcpy(d + 40, row0, 9); memcpy(d + 52, row1, 9);
        CHECK(rdp_dib_decode(d, sizeof d, &bm));
        CHECK(bm.width == 3 && bm.height == 2 && !bm.hasAlpha);
        CHECK(bm.bgra[0] == 11 && bm.bgra[1] == 12 && bm.bgra[2] == 13 && bm.bgra[3] == 255);     /* top row = stored row 1 */
        CHECK(bm.bgra[12] == 1 && bm.bgra[14] == 3);                                              /* bottom row = stored row 0 */
        free(bm.bgra);
        CHECK(!rdp_dib_decode(d, sizeof d - 1, &bm));                                             /* truncated */
        /* top-down (negative height) */
        put32(d + 8, (uint32_t)-2);
        CHECK(rdp_dib_decode(d, sizeof d, &bm));
        CHECK(bm.bgra[0] == 1 && bm.bgra[12] == 11);
        free(bm.bgra);
    }
    {   /* 32 bpp BI_RGB, alpha byte all zero => opaque; with real alpha => kept */
        uint8_t d[40 + 8] = {0};
        put32(d, 40); put32(d + 4, 2); put32(d + 8, 1); put16(d + 12, 1); put16(d + 14, 32);
        uint8_t px[8] = { 10, 20, 30, 0, 40, 50, 60, 0 };
        memcpy(d + 40, px, 8);
        CHECK(rdp_dib_decode(d, sizeof d, &bm) && !bm.hasAlpha && bm.bgra[3] == 255 && bm.bgra[7] == 255);
        free(bm.bgra);
        px[3] = 128; px[7] = 255; memcpy(d + 40, px, 8);
        CHECK(rdp_dib_decode(d, sizeof d, &bm) && bm.hasAlpha && bm.bgra[3] == 128 && bm.bgra[7] == 255);
        free(bm.bgra);
    }
    {   /* 16 bpp BI_BITFIELDS 5-6-5 with masks after a 40-byte header */
        uint8_t d[40 + 12 + 4] = {0};
        put32(d, 40); put32(d + 4, 2); put32(d + 8, 1); put16(d + 12, 1); put16(d + 14, 16); put32(d + 16, 3);
        put32(d + 40, 0xF800); put32(d + 44, 0x07E0); put32(d + 48, 0x001F);
        put16(d + 52, 0xF800); put16(d + 54, 0x07E0);   /* red, green */
        CHECK(rdp_dib_decode(d, sizeof d, &bm));
        CHECK(bm.bgra[2] == 255 && bm.bgra[1] == 0 && bm.bgra[0] == 0);
        CHECK(bm.bgra[6] == 0 && bm.bgra[5] == 255);
        free(bm.bgra);
    }
    {   /* 16 bpp BI_RGB defaults to 5-5-5 */
        uint8_t d[40 + 4] = {0};
        put32(d, 40); put32(d + 4, 2); put32(d + 8, 1); put16(d + 12, 1); put16(d + 14, 16);
        put16(d + 40, 0x7C00); put16(d + 42, 0x001F);
        CHECK(rdp_dib_decode(d, sizeof d, &bm));
        CHECK(bm.bgra[2] == 255 && bm.bgra[4] == 255 && bm.bgra[6] == 0);
        free(bm.bgra);
    }
    {   /* 8 bpp palette, 3 px wide (stride 4), bottom-up, 2 rows */
        uint8_t d[40 + 8 + 8] = {0};
        put32(d, 40); put32(d + 4, 3); put32(d + 8, 2); put16(d + 12, 1); put16(d + 14, 8); put32(d + 32, 2);
        put32(d + 40, 0x00112233);   /* idx0: B=33 G=22 R=11 */
        put32(d + 44, 0x00AABBCC);
        uint8_t rows[8] = { 0, 1, 0, 0,   1, 1, 0, 0 };   /* stored bottom row first */
        memcpy(d + 48, rows, 8);
        CHECK(rdp_dib_decode(d, sizeof d, &bm));
        CHECK(bm.bgra[0] == 0xCC && bm.bgra[2] == 0xAA);          /* top-left = stored row1[0] = idx1 */
        CHECK(bm.bgra[12] == 0x33 && bm.bgra[14] == 0x11);        /* bottom-left = idx0 */
        free(bm.bgra);
    }
    {   /* 4 bpp and 1 bpp */
        uint8_t d[40 + 8 + 4] = {0};
        put32(d, 40); put32(d + 4, 3); put32(d + 8, 1); put16(d + 12, 1); put16(d + 14, 4); put32(d + 32, 2);
        put32(d + 40, 0x00000000); put32(d + 44, 0x00FFFFFF);
        d[48] = 0x10; d[49] = 0x10;                                 /* px: 1,0,1 */
        CHECK(rdp_dib_decode(d, sizeof d, &bm));
        CHECK(bm.bgra[0] == 255 && bm.bgra[4] == 0 && bm.bgra[8] == 255);
        free(bm.bgra);
        uint8_t e[40 + 8 + 4] = {0};
        put32(e, 40); put32(e + 4, 9); put32(e + 8, 1); put16(e + 12, 1); put16(e + 14, 1); put32(e + 32, 2);
        put32(e + 40, 0x00000000); put32(e + 44, 0x00FFFFFF);
        e[48] = 0xA0; e[49] = 0x80;                                 /* bits: 1,0,1,0,0,0,0,0 | 1 */
        CHECK(rdp_dib_decode(e, sizeof e, &bm));
        CHECK(bm.bgra[0] == 255 && bm.bgra[4] == 0 && bm.bgra[8] == 255 && bm.bgra[8 * 4] == 255);
        free(bm.bgra);
    }
    {   /* unsupported: RLE8, bogus header, zero width */
        uint8_t d[40 + 16] = {0};
        put32(d, 40); put32(d + 4, 2); put32(d + 8, 2); put16(d + 12, 1); put16(d + 14, 8); put32(d + 16, 1);
        CHECK(!rdp_dib_decode(d, sizeof d, &bm));
        put32(d, 33);
        CHECK(!rdp_dib_decode(d, sizeof d, &bm));
        put32(d, 40); put32(d + 4, 0); put32(d + 16, 0);
        CHECK(!rdp_dib_decode(d, sizeof d, &bm));
    }
    {   /* V5 header, 24 bpp BI_RGB */
        uint8_t d[124 + 8] = {0};
        put32(d, 124); put32(d + 4, 2); put32(d + 8, 1); put16(d + 12, 1); put16(d + 14, 24);
        d[124] = 9; d[125] = 8; d[126] = 7; d[127] = 6; d[128] = 5; d[129] = 4;
        CHECK(rdp_dib_decode(d, sizeof d, &bm));
        CHECK(bm.bgra[0] == 9 && bm.bgra[1] == 8 && bm.bgra[2] == 7 && bm.bgra[4] == 6 && bm.bgra[6] == 4);
        free(bm.bgra);
    }
}

static void test_image(void) {
    SECTION("DIB <-> PNG / TIFF (ImageIO)");
    uint32_t w = 211, h = 97;     /* odd sizes: stride padding, not multiples of 4 */
    uint8_t *src = make_bgra(w, h, 0);
    uint8_t *dib; size_t dn;
    CHECK(rdp_dib_encode(src, w, h, false, &dib, &dn));
    RDPBitmap bm;
    CHECK(rdp_dib_decode(dib, dn, &bm));
    uint8_t *png; size_t pn;
    CHECK(rdp_image_encode(bm.bgra, bm.width, bm.height, "public.png", &png, &pn));
    CHECK(pn > 8 && memcmp(png, "\x89PNG\r\n\x1a\n", 8) == 0);
    uint8_t *back; uint32_t bw, bh; bool ha;
    CHECK(rdp_image_decode_bgra(png, pn, &back, &bw, &bh, &ha));
    CHECK(bw == w && bh == h && !ha);
    CHECK(memcmp(back, src, (size_t)w * h * 4) == 0);          /* opaque: lossless */
    /* and back to DIB: byte-identical to the original DIB */
    uint8_t *dib2; size_t dn2;
    CHECK(rdp_dib_encode(back, bw, bh, false, &dib2, &dn2));
    CHECK(dn2 == dn && memcmp(dib, dib2, dn) == 0);
    free(dib2); free(back); free(png); free(bm.bgra); free(dib);

    /* alpha PNG -> V5 -> PNG: alpha preserved, colours within premultiply rounding */
    uint8_t *asrc = make_bgra(w, h, 1);
    CHECK(rdp_image_encode(asrc, w, h, "public.png", &png, &pn));
    CHECK(rdp_image_has_alpha(png, pn));
    CHECK(rdp_image_decode_bgra(png, pn, &back, &bw, &bh, &ha) && ha);
    int maxA = 0, maxC = 0;
    for (size_t i = 0; i < (size_t)w * h; i++) {
        int da = abs(back[i * 4 + 3] - asrc[i * 4 + 3]);
        if (da > maxA) maxA = da;
        if (asrc[i * 4 + 3] >= 120)
            for (int c = 0; c < 3; c++) { int d = abs(back[i * 4 + c] - asrc[i * 4 + c]); if (d > maxC) maxC = d; }
    }
    CHECK(maxA == 0);
    CHECK(maxC <= 2);
    free(back); free(png);

    /* TIFF encode, decode */
    uint8_t *tif; size_t tn;
    CHECK(rdp_image_encode(src, w, h, "public.tiff", &tif, &tn));
    CHECK(tn > 8 && ((tif[0] == 'I' && tif[1] == 'I') || (tif[0] == 'M' && tif[1] == 'M')));
    CHECK(rdp_image_decode_bgra(tif, tn, &back, &bw, &bh, &ha));
    CHECK(bw == w && bh == h && memcmp(back, src, (size_t)w * h * 4) == 0);
    free(back); free(tif);
    CHECK(!rdp_image_decode_bgra((const uint8_t *)"not an image", 12, &back, &bw, &bh, &ha));
    free(asrc); free(src);
}

/* ── FILEDESCRIPTORW ──────────────────────────────────────────────────────── */
static void test_filelist(void) {
    SECTION("FILEDESCRIPTORW serialize/parse");
    RDPFileDesc d[4];
    memset(d, 0, sizeof d);
    d[0] = (RDPFileDesc){ RDP_FD_ATTRIBUTES | RDP_FD_WRITESTIME | RDP_FD_PROGRESSUI, RDP_FILE_ATTRIBUTE_DIRECTORY,
                          1, 2, 133000000000000000ULL, 0, strdup("My Folder") };
    d[1] = (RDPFileDesc){ RDP_FD_ATTRIBUTES | RDP_FD_FILESIZE | RDP_FD_WRITESTIME, RDP_FILE_ATTRIBUTE_NORMAL,
                          0, 0, 133000000000000001ULL, 5ULL * 1024 * 1024 * 1024 + 7, strdup("My Folder\\big.bin") };
    d[2] = (RDPFileDesc){ RDP_FD_FILESIZE, RDP_FILE_ATTRIBUTE_ARCHIVE, 0, 0, 0, 0xFFFFFFFFFFFFFFFFULL,
                          strdup("My Folder\\sub\\na\xC3\xAFve \xF0\x9F\x98\x80.txt") };
    d[3] = (RDPFileDesc){ RDP_FD_FILESIZE, RDP_FILE_ATTRIBUTE_NORMAL, 0, 0, 0, 0x1ULL << 32, strdup("z") };
    uint8_t *wire; size_t wn;
    CHECK(rdp_filelist_serialize(d, 4, &wire, &wn));
    CHECK(wn == 4 + 4 * RDP_FILEDESC_WIRE_SIZE);
    CHECK(wire[0] == 4 && wire[1] == 0);
    /* spot-check the on-wire layout of descriptor 1 (offsets from MS-RDPECLIP 2.2.5.2.3.1) */
    const uint8_t *p = wire + 4 + RDP_FILEDESC_WIRE_SIZE;
    CHECK(p[0] == 0x64 && p[1] == 0x00);                        /* flags = ATTRIBUTES|FILESIZE|WRITESTIME = 0x64 */
    CHECK(p[36] == 0x80);                                       /* dwFileAttributes at +36 */
    CHECK(p[64] == 1 && p[65] == 0 && p[66] == 0 && p[67] == 0);  /* nFileSizeHigh at +64 = 5GB>>32 = 1 */
    CHECK(p[68] == 7);                                          /* nFileSizeLow at +68 */
    CHECK(p[72] == 'M' && p[73] == 0 && p[72 + 2 * 9] == '\\' && p[72 + 2 * 17] == 0 && p[72 + 2 * 17 + 1] == 0);
    RDPFileDesc *q; uint32_t qn;
    CHECK(rdp_filelist_parse(wire, wn, &q, &qn) && qn == 4);
    for (int i = 0; i < 4; i++) {
        CHECK(q[i].flags == d[i].flags && q[i].attrs == d[i].attrs && q[i].size == d[i].size);
        CHECK(q[i].creationTime == d[i].creationTime && q[i].writeTime == d[i].writeTime);
        CHECK(strcmp(q[i].name, d[i].name) == 0);
    }
    CHECK(q[1].size == 5ULL * 1024 * 1024 * 1024 + 7);
    CHECK(q[2].size == 0xFFFFFFFFFFFFFFFFULL);
    rdp_filelist_free(q, qn);
    /* malformed input */
    CHECK(!rdp_filelist_parse(wire, 3, &q, &qn));
    CHECK(!rdp_filelist_parse(wire, wn - 1, &q, &qn));           /* count says 4, one short */
    put32(wire, 0x7FFFFFFF);
    CHECK(!rdp_filelist_parse(wire, wn, &q, &qn));
    free(wire);
    /* name length: 259 units OK, 260 rejected */
    RDPFileDesc l = { 0, 0, 0, 0, 0, 0, NULL };
    char long259[260]; memset(long259, 'a', 259); long259[259] = 0;
    l.name = long259;
    CHECK(rdp_filelist_serialize(&l, 1, &wire, &wn)); free(wire);
    char long260[261]; memset(long260, 'a', 260); long260[260] = 0;
    l.name = long260;
    CHECK(!rdp_filelist_serialize(&l, 1, &wire, &wn));
    for (int i = 0; i < 4; i++) free(d[i].name);

    /* FILETIME */
    int64_t s; long ns;
    CHECK(rdp_filetime_from_unix(0, 0) == 116444736000000000ULL);
    CHECK(rdp_filetime_to_unix(rdp_filetime_from_unix(1700000000, 123456700), &s, &ns) && s == 1700000000 && ns == 123456700);
    CHECK(!rdp_filetime_to_unix(5, &s, &ns));
}

/* ── file sets / chunked reads / downloads ────────────────────────────────── */
static char g_root[512];

static void write_file(const char *rel, const void *data, size_t n) {
    char p[1024];
    snprintf(p, sizeof p, "%s/%s", g_root, rel);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror(p); exit(2); }
    if (n && write(fd, data, n) != (ssize_t)n) { perror("write"); exit(2); }
    close(fd);
}
static void make_dir(const char *rel) {
    char p[1024];
    snprintf(p, sizeof p, "%s/%s", g_root, rel);
    mkdir(p, 0755);
}

typedef struct { RDPFileSet *set; int rangeCalls, sizeCalls; uint32_t maxLen; int failAfter; int cancelAt; volatile int *cancelFlag; } MockSrc;

static bool mock_fetch(void *user, uint32_t idx, bool sizeOnly, uint64_t pos, uint32_t len,
                       uint8_t *buf, uint32_t *got, uint64_t *sizeOut) {
    MockSrc *m = user;
    if (sizeOnly) { m->sizeCalls++; return rdp_fileset_size(m->set, idx, sizeOut); }
    m->rangeCalls++;
    if (len > m->maxLen) m->maxLen = len;
    if (m->failAfter && m->rangeCalls > m->failAfter) return false;
    if (m->cancelAt && m->rangeCalls == m->cancelAt && m->cancelFlag) *m->cancelFlag = 1;
    /* a real client may answer with fewer bytes than requested: emulate 300 KB max */
    size_t want = len > 300000 ? 300000 : len;
    ssize_t r = rdp_fileset_read(m->set, idx, pos, buf, want);
    if (r < 0) return false;
    *got = (uint32_t)r;
    return true;
}

static void sh(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
#include <stdarg.h>
static void sh(const char *fmt, ...) {
    char cmd[2048];
    va_list ap; va_start(ap, fmt); vsnprintf(cmd, sizeof cmd, fmt, ap); va_end(ap);
    if (system(cmd) != 0) { printf("  (command failed: %s)\n", cmd); }
}

static void test_files(void) {
    SECTION("file set: nested folders, ranges, >4 GB");
    char tmpl[512];
    const char *base = getenv("TEST_TMP");
    snprintf(tmpl, sizeof tmpl, "%s/clip-test-XXXXXX", base ? base : "/tmp");
    if (!mkdtemp(tmpl)) { perror("mkdtemp"); exit(2); }
    snprintf(g_root, sizeof g_root, "%s", tmpl);

    make_dir("src"); make_dir("src/Folder"); make_dir("src/Folder/sub"); make_dir("src/Folder/empty");
    make_dir("src/dest");
    char *big = malloc(2500000);
    for (size_t i = 0; i < 2500000; i++) big[i] = (char)(i * 31 + (i >> 8));
    write_file("src/Folder/a.txt", "hello world\n", 12);
    write_file("src/Folder/sub/big.bin", big, 2500000);
    write_file("src/Folder/sub/zero.dat", "", 0);
    write_file("src/Folder/sub/na\xC3\xAFve.txt", "unicode", 7);
    write_file("src/single.txt", "single file", 11);
    char p[1024];
    snprintf(p, sizeof p, "%s/src/Folder/loop", g_root); symlink(".", p);                         /* dir symlink: skipped */
    snprintf(p, sizeof p, "%s/src/Folder/link.txt", g_root); symlink("a.txt", p);                 /* file symlink: followed */
    /* sparse >4 GB file with a marker straddling the 4 GiB boundary */
    snprintf(p, sizeof p, "%s/src/huge.sparse", g_root);
    int hfd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    uint64_t hugeSize = 5ULL * 1024 * 1024 * 1024 + 123;
    CHECK(ftruncate(hfd, (off_t)hugeSize) == 0);
    CHECK(pwrite(hfd, "BOUNDARY", 8, (off_t)((1ULL << 32) - 4)) == 8);
    CHECK(pwrite(hfd, "TAIL", 4, (off_t)(hugeSize - 4)) == 4);
    close(hfd);

    char pA[1024], pB[1024], pC[1024], pD[1024];
    snprintf(pA, sizeof pA, "%s/src/Folder", g_root);
    snprintf(pB, sizeof pB, "%s/src/single.txt", g_root);
    snprintf(pC, sizeof pC, "%s/src/huge.sparse", g_root);
    snprintf(pD, sizeof pD, "%s/src/Folder/", g_root);          /* trailing slash */
    const char *paths[3] = { pA, pB, pC };
    RDPFileSet *set = rdp_fileset_create(paths, 3, true);
    const RDPFileDesc *d; uint32_t n;
    CHECK(rdp_fileset_descriptors(set, &d, &n));
    /* Folder, a.txt, empty, link.txt, sub, sub\big.bin, sub\naïve.txt, sub\zero.dat, single.txt, huge.sparse (loop symlink skipped) */
    CHECK(n == 10);
    CHECK(strcmp(d[0].name, "Folder") == 0 && (d[0].attrs & RDP_FILE_ATTRIBUTE_DIRECTORY));
    CHECK(strcmp(d[1].name, "Folder\\a.txt") == 0 && d[1].size == 12 && (d[1].flags & RDP_FD_FILESIZE));
    CHECK(strcmp(d[2].name, "Folder\\empty") == 0 && (d[2].attrs & RDP_FILE_ATTRIBUTE_DIRECTORY));
    CHECK(strcmp(d[3].name, "Folder\\link.txt") == 0 && d[3].size == 12);
    CHECK(strcmp(d[4].name, "Folder\\sub") == 0);
    int sawLoop = 0, parentBeforeChild = 1;
    for (uint32_t i = 0; i < n; i++) {
        if (strstr(d[i].name, "loop")) sawLoop = 1;
        char *bs = strrchr(d[i].name, '\\');
        if (bs) {
            size_t pl = (size_t)(bs - d[i].name); int found = 0;
            for (uint32_t j = 0; j < i; j++)
                if (strlen(d[j].name) == pl && strncmp(d[j].name, d[i].name, pl) == 0 &&
                    (d[j].attrs & RDP_FILE_ATTRIBUTE_DIRECTORY)) found = 1;
            if (!found) parentBeforeChild = 0;
        }
        CHECK(d[i].writeTime > 116444736000000000ULL);
        CHECK((d[i].flags & RDP_FD_ATTRIBUTES) && (d[i].flags & RDP_FD_WRITESTIME));
    }
    CHECK(!sawLoop);
    CHECK(parentBeforeChild);
    uint32_t bigIdx = 0, hugeIdx = 0, singleIdx = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (!strcmp(d[i].name, "Folder\\sub\\big.bin")) bigIdx = i;
        if (!strcmp(d[i].name, "huge.sparse")) hugeIdx = i;
        if (!strcmp(d[i].name, "single.txt")) singleIdx = i;
    }
    CHECK(bigIdx && d[bigIdx].size == 2500000);
    CHECK(hugeIdx && d[hugeIdx].size == hugeSize);
    uint8_t *wire; size_t wn;
    CHECK(rdp_fileset_serialize(set, &wire, &wn) && wn == 4 + (size_t)n * 592);
    RDPFileDesc *rt; uint32_t rtn;
    CHECK(rdp_filelist_parse(wire, wn, &rt, &rtn) && rtn == n && rt[hugeIdx].size == hugeSize);
    rdp_filelist_free(rt, rtn); free(wire);

    /* chunked range reads reassemble the file; short read at EOF; past EOF = 0 */
    uint8_t *acc = malloc(2500000); size_t total = 0; int chunks = 0;
    while (total < 2500000) {
        uint8_t buf[700000];
        ssize_t r = rdp_fileset_read(set, bigIdx, total, buf, sizeof buf);
        CHECK(r > 0);
        if (r <= 0) break;
        memcpy(acc + total, buf, (size_t)r); total += (size_t)r; chunks++;
    }
    CHECK(total == 2500000 && chunks == 4 && memcmp(acc, big, 2500000) == 0);
    uint8_t one[16];
    CHECK(rdp_fileset_read(set, bigIdx, 2500000, one, 16) == 0);
    CHECK(rdp_fileset_read(set, bigIdx, 2499990, one, 16) == 10);
    CHECK(rdp_fileset_read(set, 0, 0, one, 16) == -1);            /* directory */
    CHECK(rdp_fileset_read(set, 9999, 0, one, 16) == -1);
    free(acc);
    /* >4 GB offsets (nPositionHigh != 0) */
    uint8_t m[8];
    CHECK(rdp_fileset_read(set, hugeIdx, (1ULL << 32) - 4, m, 8) == 8 && memcmp(m, "BOUNDARY", 8) == 0);
    CHECK(rdp_fileset_read(set, hugeIdx, hugeSize - 4, m, 8) == 4 && memcmp(m, "TAIL", 4) == 0);
    uint64_t sz = 0;
    CHECK(rdp_fileset_size(set, hugeIdx, &sz) && sz == hugeSize);
    CHECK(rdp_fileset_size(set, singleIdx, &sz) && sz == 11);
    rdp_fileset_release(set);

    /* without huge-file support, >= 2 GB files are left out of the list */
    RDPFileSet *noHuge = rdp_fileset_create(paths, 3, false);
    CHECK(rdp_fileset_descriptors(noHuge, &d, &n) && n == 9);
    for (uint32_t i = 0; i < n; i++) CHECK(strcmp(d[i].name, "huge.sparse") != 0);
    rdp_fileset_release(noHuge);

    /* trailing slash and nonexistent top-level entries */
    const char *p2[2] = { pD, "/nonexistent/zzz" };
    RDPFileSet *s2 = rdp_fileset_create(p2, 2, true);
    CHECK(rdp_fileset_descriptors(s2, &d, &n) && n == 8 && strcmp(d[0].name, "Folder") == 0);
    rdp_fileset_release(s2);
    const char *p3[1] = { "/nonexistent/zzz" };
    RDPFileSet *s3 = rdp_fileset_create(p3, 1, true);
    CHECK(!rdp_fileset_descriptors(s3, &d, &n));
    rdp_fileset_release(s3);

    SECTION("download: folder tree, chunking, failure, cancel, hostile names");
    const char *p4[2] = { pA, pB };
    RDPFileSet *s4 = rdp_fileset_create(p4, 2, true);
    CHECK(rdp_fileset_descriptors(s4, &d, &n));
    /* The client's view of the list = parsed wire data */
    rdp_fileset_serialize(s4, &wire, &wn);
    rdp_filelist_parse(wire, wn, &rt, &rtn); free(wire);
    uint32_t tops[16];
    uint32_t nt = rdp_clipfiles_top_entries(rt, rtn, tops, 16);
    CHECK(nt == 2 && strcmp(rt[tops[0]].name, "Folder") == 0 && strcmp(rt[tops[1]].name, "single.txt") == 0);
    char dest[1024]; snprintf(dest, sizeof dest, "%s/dl", g_root);
    MockSrc ms = { s4, 0, 0, 0, 0, 0, NULL };
    const char *err = NULL;
    char *out = rdp_clipfiles_download(rt, rtn, tops[0], dest, mock_fetch, &ms, NULL, &err);
    CHECK(out != NULL);
    if (out) {
        char expect[1024]; snprintf(expect, sizeof expect, "%s/Folder", dest);
        CHECK(strcmp(out, expect) == 0);
        char cmd[2048];
        snprintf(cmd, sizeof cmd, "diff -r -x loop -x link.txt '%s/src/Folder' '%s/dl/Folder' >/dev/null", g_root, g_root);
        CHECK(system(cmd) == 0);
        snprintf(cmd, sizeof cmd, "test -d '%s/dl/Folder/empty' && test -f '%s/dl/Folder/link.txt' && cmp -s '%s/src/Folder/a.txt' '%s/dl/Folder/link.txt'", g_root, g_root, g_root, g_root);
        CHECK(system(cmd) == 0);
        /* mtime restored from the descriptor */
        struct stat a, b;
        snprintf(p, sizeof p, "%s/src/Folder/a.txt", g_root); stat(p, &a);
        snprintf(p, sizeof p, "%s/dl/Folder/a.txt", g_root); stat(p, &b);
        CHECK(a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec);
        free(out);
    }
    CHECK(ms.maxLen <= RDP_CLIPFILES_CHUNK);                       /* ~1 MB request size */
    CHECK(ms.rangeCalls >= 9);                                     /* 2.5 MB at <=300 KB/answer */
    CHECK(ms.sizeCalls == 0);                                      /* FD_FILESIZE present: no SIZE requests */
    out = rdp_clipfiles_download(rt, rtn, tops[1], dest, mock_fetch, &ms, NULL, &err);
    CHECK(out != NULL);
    if (out) { CHECK(strcmp(out + strlen(out) - 10, "single.txt") == 0); free(out); }

    /* descriptors without FD_FILESIZE force FILECONTENTS_SIZE requests */
    for (uint32_t i = 0; i < rtn; i++) rt[i].flags &= ~RDP_FD_FILESIZE;
    snprintf(dest, sizeof dest, "%s/dl2", g_root);
    ms = (MockSrc){ s4, 0, 0, 0, 0, 0, NULL };
    out = rdp_clipfiles_download(rt, rtn, tops[1], dest, mock_fetch, &ms, NULL, &err);
    CHECK(out && ms.sizeCalls == 1 && ms.rangeCalls == 1);
    free(out);

    /* failure mid-file: NULL, and the partial file is removed */
    snprintf(dest, sizeof dest, "%s/dl3", g_root);
    for (uint32_t i = 0; i < rtn; i++) rt[i].flags |= RDP_FD_FILESIZE;
    ms = (MockSrc){ s4, 0, 0, 0, 2, 0, NULL };
    out = rdp_clipfiles_download(rt, rtn, tops[0], dest, mock_fetch, &ms, NULL, &err);
    CHECK(out == NULL && err != NULL);
    snprintf(p, sizeof p, "%s/dl3/Folder/sub/big.bin", g_root);
    CHECK(access(p, F_OK) != 0);

    /* cancel */
    volatile int cancel = 0;
    snprintf(dest, sizeof dest, "%s/dl4", g_root);
    ms = (MockSrc){ s4, 0, 0, 0, 0, 3, &cancel };
    out = rdp_clipfiles_download(rt, rtn, tops[0], dest, mock_fetch, &ms, &cancel, &err);
    CHECK(out == NULL && err && !strcmp(err, "cancelled"));

    /* hostile descriptors: traversal / absolute / empty components */
    snprintf(dest, sizeof dest, "%s/dl5", g_root);
    RDPFileDesc evil[3];
    memset(evil, 0, sizeof evil);
    evil[0] = (RDPFileDesc){ RDP_FD_FILESIZE, 0x80, 0, 0, 0, 1, strdup("..") };
    evil[1] = (RDPFileDesc){ RDP_FD_FILESIZE | RDP_FD_ATTRIBUTES, RDP_FILE_ATTRIBUTE_DIRECTORY, 0, 0, 0, 0, strdup("dir") };
    evil[2] = (RDPFileDesc){ RDP_FD_FILESIZE, 0x80, 0, 0, 0, 1, strdup("dir\\..\\..\\escape.txt") };
    CHECK(rdp_clipfiles_download(evil, 3, 0, dest, mock_fetch, &ms, NULL, &err) == NULL);
    CHECK(rdp_clipfiles_download(evil, 3, 1, dest, mock_fetch, &ms, NULL, &err) == NULL);
    snprintf(p, sizeof p, "%s/escape.txt", g_root);
    CHECK(access(p, F_OK) != 0);
    snprintf(p, sizeof p, "%s/dl5/escape.txt", g_root);
    CHECK(access(p, F_OK) != 0);
    for (int i = 0; i < 3; i++) free(evil[i].name);
    char comp[300];
    CHECK(!rdp_clipfiles_safe_component("..", 2, comp, sizeof comp));
    CHECK(!rdp_clipfiles_safe_component("", 0, comp, sizeof comp));
    CHECK(rdp_clipfiles_safe_component("a/b", 3, comp, sizeof comp) && strcmp(comp, "a_b") == 0);
    char longn[400]; memset(longn, 'x', 399); longn[399] = 0;
    CHECK(rdp_clipfiles_safe_component(longn, 399, comp, sizeof comp) && strlen(comp) == 255);

    rdp_filelist_free(rt, rtn);
    rdp_fileset_release(s4);
    free(big);
    sh("rm -rf '%s'", g_root);
}

int main(void) {
    test_utf();
    test_html();
    test_dib();
    test_image();
    test_filelist();
    test_files();
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
