#pragma once
/*
 * Pure-C clipboard format codecs for MS-RDPECLIP. No FreeRDP, no ObjC, no
 * CoreFoundation: everything here is unit-testable with plain clang (tests/).
 *
 *   - CF_HTML ("HTML Format") build / parse
 *   - CF_DIB / CF_DIBV5 <-> 32-bit straight-alpha BGRA (top-down)
 *   - FILEDESCRIPTORW list (CLIPRDR_FILELIST) serialize / parse
 *   - UTF-8 <-> UTF-16LE helpers
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Windows clipboard format ids / names used by the daemon ──────────────── */
#define RDP_CF_TEXT          1
#define RDP_CF_BITMAP        2
#define RDP_CF_OEMTEXT       7
#define RDP_CF_DIB           8
#define RDP_CF_UNICODETEXT   13
#define RDP_CF_DIBV5         17

#define RDP_FMT_NAME_HTML    "HTML Format"
#define RDP_FMT_NAME_RTF     "Rich Text Format"
#define RDP_FMT_NAME_PNG     "PNG"
#define RDP_FMT_NAME_FILES   "FileGroupDescriptorW"

/* ── CF_HTML ──────────────────────────────────────────────────────────────── */

/* Wrap UTF-8 HTML (a fragment or a whole document) into CF_HTML: ASCII header
 * with fixed-width Version/StartHTML/EndHTML/StartFragment/EndFragment byte
 * offsets, the <!--StartFragment--> / <!--EndFragment--> markers, and a trailing
 * NUL. *out is malloc'd. */
bool rdp_cf_html_build(const uint8_t *html, size_t len, uint8_t **out, size_t *outLen);

/* Locate the HTML document (StartHTML..EndHTML) and the fragment
 * (StartFragment..EndFragment) inside CF_HTML data. Both are pointers INTO data.
 * Tolerates a missing/garbled header (falls back to the markers, then to the
 * whole payload) and trailing NULs. */
bool rdp_cf_html_parse(const uint8_t *data, size_t len,
                       const uint8_t **html, size_t *htmlLen,
                       const uint8_t **frag, size_t *fragLen);

/* ── DIB ──────────────────────────────────────────────────────────────────── */

typedef struct {
    uint32_t width, height;
    uint8_t *bgra;     /* malloc'd, width*height*4, top-down, NON-premultiplied */
    bool     hasAlpha; /* source carried a usable alpha channel */
} RDPBitmap;

/* Decode CF_DIB / CF_DIBV5 data (BITMAPINFOHEADER..BITMAPV5HEADER, no file
 * header). Handles 1/4/8 bpp palettes, 16/24/32 bpp, BI_RGB / BI_BITFIELDS /
 * BI_ALPHABITFIELDS, bottom-up and top-down. RLE and embedded JPEG/PNG DIBs are
 * rejected (return false). */
bool rdp_dib_decode(const uint8_t *dib, size_t len, RDPBitmap *out);

/* Encode straight-alpha top-down BGRA as a bottom-up 32 bpp DIB.
 *   v5 == false: BITMAPINFOHEADER / BI_RGB, composited over white (alpha is not
 *                reliably honoured by CF_DIB consumers).
 *   v5 == true : BITMAPV5HEADER / BI_BITFIELDS with an alpha mask, sRGB. */
bool rdp_dib_encode(const uint8_t *bgra, uint32_t w, uint32_t h, bool v5,
                    uint8_t **out, size_t *outLen);

/* ── FILEDESCRIPTORW list ─────────────────────────────────────────────────── */

#define RDP_FD_ATTRIBUTES  0x00000004u
#define RDP_FD_CREATETIME  0x00000008u
#define RDP_FD_ACCESSTIME  0x00000010u
#define RDP_FD_WRITESTIME  0x00000020u
#define RDP_FD_FILESIZE    0x00000040u
#define RDP_FD_PROGRESSUI  0x00004000u

#define RDP_FILE_ATTRIBUTE_READONLY   0x00000001u
#define RDP_FILE_ATTRIBUTE_HIDDEN     0x00000002u
#define RDP_FILE_ATTRIBUTE_DIRECTORY  0x00000010u
#define RDP_FILE_ATTRIBUTE_ARCHIVE    0x00000020u
#define RDP_FILE_ATTRIBUTE_NORMAL     0x00000080u

#define RDP_FD_NAME_MAX_UNITS 259   /* cFileName is WCHAR[260] incl. terminator */

typedef struct {
    uint32_t flags;          /* FD_* */
    uint32_t attrs;          /* FILE_ATTRIBUTE_* */
    uint64_t creationTime;   /* FILETIME: 100 ns ticks since 1601-01-01 */
    uint64_t accessTime;
    uint64_t writeTime;
    uint64_t size;
    char    *name;           /* UTF-8, relative path with '\\' separators; malloc'd */
} RDPFileDesc;

#define RDP_FILEDESC_WIRE_SIZE 592

/* Serialize to CLIPRDR_FILELIST (cItems + n * 592-byte FILEDESCRIPTORW).
 * Fails if a name needs more than RDP_FD_NAME_MAX_UNITS UTF-16 units. */
bool rdp_filelist_serialize(const RDPFileDesc *d, uint32_t n, uint8_t **out, size_t *outLen);

/* Parse a CLIPRDR_FILELIST. *out and every name are malloc'd; release with
 * rdp_filelist_free. On failure nothing is returned. */
bool rdp_filelist_parse(const uint8_t *data, size_t len, RDPFileDesc **out, uint32_t *n);
void rdp_filelist_free(RDPFileDesc *d, uint32_t n);

/* Unix time (seconds + nanoseconds) <-> FILETIME. */
uint64_t rdp_filetime_from_unix(int64_t sec, long nsec);
bool     rdp_filetime_to_unix(uint64_t ft, int64_t *sec, long *nsec);

/* ── UTF helpers ──────────────────────────────────────────────────────────── */

/* UTF-8 -> UTF-16LE code units. Returns the number of units written (excluding
 * the terminator, which is always appended when cap > 0), or (size_t)-1 if the
 * result would not fit in `cap` units or the input is not valid UTF-8. */
size_t rdp_utf8_to_utf16(const char *s, uint16_t *dst, size_t cap);
/* UTF-16 code units (len units, not NUL-terminated) -> malloc'd UTF-8 string. */
char  *rdp_utf16_to_utf8(const uint16_t *s, size_t len);

#ifdef __cplusplus
}
#endif
