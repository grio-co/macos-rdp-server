#ifndef MACOS_RDP_UPDATE_VERSION_H
#define MACOS_RDP_UPDATE_VERSION_H
/* Release-tag version parsing/comparison for the auto-updater (header-only so
 * tests/run.sh can exercise it without linking the daemon). */
#include <stdlib.h>
#include <string.h>

#define UPDATE_VER_MAX 8

/* Parse "v0.1.7" / "1.2" into numeric fields. At least two dotted fields are
 * required (so an all-digit git short SHA is not a version), and a suffix such
 * as "-rc1" or "+x" is rejected so a pre-release can never pass as final.
 * Returns the field count, or 0 when the string is not a version tag. */
static inline int update_version_parse(const char *s, unsigned long out[UPDATE_VER_MAX]) {
    if (!s) return 0;
    if (*s == 'v' || *s == 'V') s++;
    int n = 0;
    for (;;) {
        if (*s < '0' || *s > '9') return 0;
        unsigned long v = 0;
        int digits = 0;
        while (*s >= '0' && *s <= '9') {
            if (++digits > 9) return 0;
            v = v * 10 + (unsigned long)(*s - '0');
            s++;
        }
        if (n >= UPDATE_VER_MAX) return 0;
        out[n++] = v;
        if (*s == '.') { s++; continue; }
        if (*s == '\0') return n >= 2 ? n : 0;
        return 0;
    }
}

/* Compare two version tags field by field (missing fields count as 0).
 * Returns -1/0/1 for a<b / a==b / a>b, or -2 if either is not parseable. */
static inline int update_version_compare(const char *a, const char *b) {
    unsigned long x[UPDATE_VER_MAX], y[UPDATE_VER_MAX];
    int nx = update_version_parse(a, x), ny = update_version_parse(b, y);
    if (nx == 0 || ny == 0) return -2;
    int n = nx > ny ? nx : ny;
    for (int i = 0; i < n; i++) {
        unsigned long p = i < nx ? x[i] : 0, q = i < ny ? y[i] : 0;
        if (p != q) return p < q ? -1 : 1;
    }
    return 0;
}
#endif
