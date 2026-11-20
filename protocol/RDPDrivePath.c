#define __STDC_WANT_LIB_EXT1__ 1   /* memset_s: a wipe the compiler keeps */
#include "protocol/RDPDrivePath.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* NUL-terminates what fits after a failed write and returns false. */
static bool fail_terminated(char *out, size_t outCap, size_t n) {
    if (outCap > 0) out[n < outCap ? n : outCap - 1] = '\0';
    return false;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool rdp_url_decode(char *s) {
    if (!s) return false;
    char *r = s, *w = s;
    while (*r) {
        if (*r == '%') {
            int hi = hexval(r[1]);
            int lo = hi >= 0 ? hexval(r[2]) : -1;   /* r[2] exists when r[1] is a digit */
            if (hi < 0 || lo < 0 || (hi == 0 && lo == 0)) { *w = '\0'; return false; }
            *w++ = (char)(hi * 16 + lo);
            r += 3;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
    return true;
}

const char *rdp_url_path_part(const char *url) {
    if (!url) return "";
    const char *p = strstr(url, "://");
    if (!p) return url;
    const char *slash = strchr(p + 3, '/');
    return slash ? slash : "";
}

bool rdpdr_path_from_url(const char *urlPath, char *out, size_t outCap) {
    if (!out || outCap == 0) return false;
    out[0] = '\0';
    if (!urlPath) return false;
    size_t n = 0;
    const char *p = urlPath;
    for (;;) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *seg = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - seg);
        if ((len == 1 && seg[0] == '.') || (len == 2 && seg[0] == '.' && seg[1] == '.'))
            return fail_terminated(out, outCap, 0);
        for (size_t i = 0; i < len; i++)
            if (seg[i] == '\\' || seg[i] == ':') return fail_terminated(out, outCap, 0);
        if (n + 1 + len + 1 > outCap) return fail_terminated(out, outCap, 0);
        out[n++] = '\\';
        memcpy(out + n, seg, len);
        n += len;
    }
    out[n] = '\0';
    return true;
}

size_t rdpdr_utf8_to_utf16le(const char *in, uint8_t *out, size_t outCap) {
    if (!in || !out) return 0;
    const unsigned char *s = (const unsigned char *)in;
    size_t n = 0;
    while (*s) {
        unsigned char c = *s++;
        uint32_t cp;
        int extra;
        if (c < 0x80)                { cp = c;        extra = 0; }
        else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; extra = 1; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; extra = 2; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; extra = 3; }
        else return 0;
        for (int i = 0; i < extra; i++, s++) {
            if ((*s & 0xC0) != 0x80) return 0;   /* also stops at the NUL */
            cp = (cp << 6) | (*s & 0x3F);
        }
        if ((extra == 1 && cp < 0x80) || (extra == 2 && cp < 0x800) ||
            (extra == 3 && cp < 0x10000) || cp > 0x10FFFF ||
            (cp >= 0xD800 && cp <= 0xDFFF))
            return 0;                            /* overlong, out of range, surrogate */
        if (cp >= 0x10000) {
            if (n + 4 > outCap) return 0;
            cp -= 0x10000;
            uint16_t hi = (uint16_t)(0xD800 | (cp >> 10));
            uint16_t lo = (uint16_t)(0xDC00 | (cp & 0x3FF));
            out[n++] = (uint8_t)(hi & 0xFF); out[n++] = (uint8_t)(hi >> 8);
            out[n++] = (uint8_t)(lo & 0xFF); out[n++] = (uint8_t)(lo >> 8);
        } else {
            if (n + 2 > outCap) return 0;
            out[n++] = (uint8_t)(cp & 0xFF); out[n++] = (uint8_t)(cp >> 8);
        }
    }
    if (n + 2 > outCap) return 0;
    out[n++] = 0;
    out[n++] = 0;
    return n;
}

bool rdpdr_utf16le_to_utf8(const uint8_t *in, size_t inBytes, char *out, size_t outCap) {
    if (!out || outCap == 0) return false;
    size_t n = 0, i = 0;
    while (in && i + 1 < inBytes) {
        uint32_t cp = (uint32_t)in[i] | ((uint32_t)in[i + 1] << 8);
        i += 2;
        if (cp == 0) break;
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            uint32_t lo = (i + 1 < inBytes) ? ((uint32_t)in[i] | ((uint32_t)in[i + 1] << 8)) : 0;
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            } else {
                cp = 0xFFFD;
            }
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            cp = 0xFFFD;
        }
        unsigned char b[4];
        size_t len;
        if (cp < 0x80)         { b[0] = (unsigned char)cp; len = 1; }
        else if (cp < 0x800)   { b[0] = (unsigned char)(0xC0 | (cp >> 6));
                                 b[1] = (unsigned char)(0x80 | (cp & 0x3F)); len = 2; }
        else if (cp < 0x10000) { b[0] = (unsigned char)(0xE0 | (cp >> 12));
                                 b[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
                                 b[2] = (unsigned char)(0x80 | (cp & 0x3F)); len = 3; }
        else                   { b[0] = (unsigned char)(0xF0 | (cp >> 18));
                                 b[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
                                 b[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
                                 b[3] = (unsigned char)(0x80 | (cp & 0x3F)); len = 4; }
        if (n + len + 1 > outCap) return fail_terminated(out, outCap, n);
        memcpy(out + n, b, len);
        n += len;
    }
    out[n] = '\0';
    return true;
}

bool rdp_url_path_encode(const char *in, char *out, size_t outCap) {
    static const char hex[] = "0123456789ABCDEF";
    if (!out || outCap == 0) return false;
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)(in ? in : ""); *p; p++) {
        unsigned char c = *p;
        bool keep = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
                    c == '~' || c == '/';
        if (keep) {
            if (n + 2 > outCap) return fail_terminated(out, outCap, n);
            out[n++] = (char)c;
        } else {
            if (n + 4 > outCap) return fail_terminated(out, outCap, n);
            out[n++] = '%';
            out[n++] = hex[c >> 4];
            out[n++] = hex[c & 15];
        }
    }
    out[n] = '\0';
    return true;
}

bool rdp_xml_escape(const char *in, char *out, size_t outCap) {
    if (!out || outCap == 0) return false;
    size_t n = 0;
    for (const char *p = in ? in : ""; *p; p++) {
        char one[2] = { *p, '\0' };
        const char *rep = one;
        switch (*p) {
            case '&':  rep = "&amp;";  break;
            case '<':  rep = "&lt;";   break;
            case '>':  rep = "&gt;";   break;
            case '"':  rep = "&quot;"; break;
            case '\'': rep = "&apos;"; break;
            default: break;
        }
        size_t len = strlen(rep);
        if (n + len + 1 > outCap) return fail_terminated(out, outCap, n);
        memcpy(out + n, rep, len);
        n += len;
    }
    out[n] = '\0';
    return true;
}

void rdp_http_date_from_filetime(uint64_t filetime, char *out, size_t outCap) {
    static const char *const wd[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    static const char *const mo[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const uint64_t unixEpoch = 116444736000000000ULL;   /* 1970-01-01 in FILETIME */
    if (!out || outCap == 0) return;
    time_t t = filetime > unixEpoch ? (time_t)((filetime - unixEpoch) / 10000000ULL) : 0;
    struct tm tm;
    if (!gmtime_r(&t, &tm)) { t = 0; gmtime_r(&t, &tm); }
    snprintf(out, outCap, "%s, %02d %s %04d %02d:%02d:%02d GMT",
             wd[tm.tm_wday], tm.tm_mday, mo[tm.tm_mon], tm.tm_year + 1900,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool rdp_base64_encode(const uint8_t *in, size_t inLen, char *out, size_t outCap) {
    if (!out || outCap == 0) return false;
    out[0] = '\0';
    size_t need = (inLen + 2) / 3 * 4 + 1;
    if (inLen > (SIZE_MAX - 3) / 4 || need > outCap) return false;
    size_t o = 0;
    for (size_t i = 0; i < inLen; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < inLen) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < inLen) v |= in[i + 2];
        out[o++] = kB64[(v >> 18) & 63];
        out[o++] = kB64[(v >> 12) & 63];
        out[o++] = i + 1 < inLen ? kB64[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < inLen ? kB64[v & 63] : '=';
    }
    out[o] = '\0';
    return true;
}

static int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

long rdp_base64_decode(const char *in, size_t inLen, uint8_t *out, size_t outCap) {
    if (!in) return -1;
    /* Padding only at the end, at most two, and only to fill a 4-char group. */
    size_t pad = 0;
    while (pad < 2 && inLen > pad && in[inLen - 1 - pad] == '=') pad++;
    if (pad && inLen % 4 != 0) return -1;
    size_t n = inLen - pad;
    if (n % 4 == 1) return -1;
    size_t outLen = n / 4 * 3 + (n % 4 ? n % 4 - 1 : 0);
    if (outLen > outCap || outLen > (size_t)LONG_MAX) return -1;
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        int v = b64_value(in[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    /* The bits left over must be zero, or the encoding isn't canonical. */
    if (bits && (acc & ((1u << bits) - 1))) return -1;
    return (long)o;
}

bool rdp_http_basic_auth_ok(const char *value, size_t len, const char *expectUserPass) {
    if (!value || !expectUserPass || !*expectUserPass) return false;
    if (len < 6 || strncasecmp(value, "Basic", 5) != 0 || (value[5] != ' ' && value[5] != '\t'))
        return false;
    size_t i = 5;
    while (i < len && (value[i] == ' ' || value[i] == '\t')) i++;
    uint8_t got[384];
    long gotLen = rdp_base64_decode(value + i, len - i, got, sizeof(got));
    if (gotLen < 0) return false;
    /* Runs over the expected bytes whatever was sent, so the time says nothing
     * about where (or whether) the two first differ. */
    const uint8_t *want = (const uint8_t *)expectUserPass;
    size_t wantLen = strlen(expectUserPass);
    uint8_t diff = (uint8_t)((size_t)gotLen != wantLen);
    for (size_t k = 0; k < wantLen; k++)
        diff |= (uint8_t)(want[k] ^ ((size_t)k < (size_t)gotLen ? got[k] : 0));
    memset_s(got, sizeof(got), 0, sizeof(got));
    return diff == 0;
}
