#include "daemon/SecurityCore.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── MD4 (RFC 1320) ──────────────────────────────────────────────────────── */

#define MD4_F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define MD4_G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_H(x, y, z) ((x) ^ (y) ^ (z))
#define ROL32(x, n)    (((x) << (n)) | ((x) >> (32 - (n))))

static void md4_block(uint32_t st[4], const uint8_t blk[64]) {
    uint32_t X[16];
    for (int i = 0; i < 16; i++)
        X[i] = (uint32_t)blk[i * 4] | ((uint32_t)blk[i * 4 + 1] << 8) |
               ((uint32_t)blk[i * 4 + 2] << 16) | ((uint32_t)blk[i * 4 + 3] << 24);

    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], t;

    static const int s1[4] = {3, 7, 11, 19};
    for (int i = 0; i < 16; i++) {
        t = ROL32(a + MD4_F(b, c, d) + X[i], s1[i & 3]);
        a = d; d = c; c = b; b = t;
    }
    static const int s2[4] = {3, 5, 9, 13};
    for (int i = 0; i < 16; i++) {
        int k = (i & 3) * 4 + (i >> 2);
        t = ROL32(a + MD4_G(b, c, d) + X[k] + 0x5A827999u, s2[i & 3]);
        a = d; d = c; c = b; b = t;
    }
    static const int s3[4] = {3, 9, 11, 15};
    static const int k3[16] = {0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};
    for (int i = 0; i < 16; i++) {
        t = ROL32(a + MD4_H(b, c, d) + X[k3[i]] + 0x6ED9EBA1u, s3[i & 3]);
        a = d; d = c; c = b; b = t;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
}

void sc_md4(const uint8_t *data, size_t len, uint8_t out[16]) {
    uint32_t st[4] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
    size_t i = 0;
    for (; i + 64 <= len; i += 64) md4_block(st, data + i);

    uint8_t tail[128] = {0};
    size_t rem = len - i;
    if (rem) memcpy(tail, data + i, rem);
    tail[rem] = 0x80;
    size_t tl = (rem < 56) ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int k = 0; k < 8; k++) tail[tl - 8 + k] = (uint8_t)(bits >> (8 * k));
    md4_block(st, tail);
    if (tl == 128) md4_block(st, tail + 64);

    for (int k = 0; k < 4; k++)
        for (int j = 0; j < 4; j++) out[k * 4 + j] = (uint8_t)(st[k] >> (8 * j));
}

int sc_nt_hash_utf8(const char *pw, uint8_t out[16]) {
    if (!pw) return -1;
    size_t n = strlen(pw);
    if (n > 1024) return -1;
    uint8_t buf[2 * 1024 + 4];
    size_t o = 0;
    const unsigned char *p = (const unsigned char *)pw;
    size_t i = 0;
    while (i < n) {
        uint32_t cp;
        unsigned c = p[i];
        size_t extra;
        if (c < 0x80)            { cp = c;        extra = 0; }
        else if ((c >> 5) == 6)  { cp = c & 0x1F; extra = 1; }
        else if ((c >> 4) == 14) { cp = c & 0x0F; extra = 2; }
        else if ((c >> 3) == 30) { cp = c & 0x07; extra = 3; }
        else return -1;
        for (size_t k = 1; k <= extra; k++) {
            if (i + k >= n || (p[i + k] & 0xC0) != 0x80) return -1;
            cp = (cp << 6) | (p[i + k] & 0x3F);
        }
        i += extra + 1;
        if ((extra == 1 && cp < 0x80) || (extra == 2 && cp < 0x800) ||
            (extra == 3 && cp < 0x10000) || cp > 0x10FFFF ||
            (cp >= 0xD800 && cp <= 0xDFFF))
            return -1;
        if (cp >= 0x10000) {
            cp -= 0x10000;
            uint16_t hi = (uint16_t)(0xD800 + (cp >> 10));
            uint16_t lo = (uint16_t)(0xDC00 + (cp & 0x3FF));
            buf[o++] = (uint8_t)(hi & 0xFF); buf[o++] = (uint8_t)(hi >> 8);
            buf[o++] = (uint8_t)(lo & 0xFF); buf[o++] = (uint8_t)(lo >> 8);
        } else {
            buf[o++] = (uint8_t)(cp & 0xFF); buf[o++] = (uint8_t)(cp >> 8);
        }
    }
    sc_md4(buf, o, out);
    memset(buf, 0, sizeof(buf));
    return 0;
}

void sc_hex_upper(const uint8_t *in, size_t n, char *out) {
    static const char *H = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = H[in[i] >> 4];
        out[2 * i + 1] = H[in[i] & 15];
    }
    out[2 * n] = '\0';
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ── SAM text ────────────────────────────────────────────────────────────── */

int sc_sam_name_ok(const char *name) {
    if (!name || !*name || name[0] == '#') return 0;
    size_t n = strlen(name);
    if (n >= SC_SAM_NAME_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c == ':' || c < 0x20 || c == 0x7F) return 0;
    }
    return 1;
}

int sc_sam_format_line(const char *alias, const char *owner,
                       const uint8_t nt[16], char *out, size_t outsz) {
    if (!sc_sam_name_ok(alias) || !sc_sam_name_ok(owner)) return -1;
    char hex[33];
    sc_hex_upper(nt, 16, hex);
    int n = snprintf(out, outsz, "%s:::%s:%s:", alias, hex, owner);
    if (n < 0 || (size_t)n >= outsz) return -1;
    return n;
}

int sc_sam_parse_line(const char *line, sc_sam_entry *e) {
    if (!line || !e) return -1;
    size_t len = strlen(line);
    while (len && (line[len - 1] == '\r' || line[len - 1] == '\n')) len--;
    if (len < 2 || line[0] == '#') return -1;

    /* Split on the first five ':' (WinPR needs >= 4). */
    const char *f[6];
    size_t nf = 0;
    f[nf++] = line;
    for (size_t i = 0; i < len && nf < 6; i++)
        if (line[i] == ':') f[nf++] = line + i + 1;
    if (nf < 5) return -1;

    size_t ulen = (size_t)(f[1] - f[0] - 1);
    size_t dlen = (size_t)(f[2] - f[1] - 1);
    size_t llen = (size_t)(f[3] - f[2] - 1);
    size_t nlen = (size_t)(f[4] - f[3] - 1);
    (void)dlen;
    if (llen != 0 && llen != 32) return -1;
    if (nlen != 32) return -1;
    if (ulen == 0 || ulen >= SC_SAM_NAME_MAX) return -1;

    memset(e, 0, sizeof(*e));
    memcpy(e->user, f[0], ulen);
    for (int i = 0; i < 16; i++) {
        int h = hexval(f[3][2 * i]), l = hexval(f[3][2 * i + 1]);
        if (h < 0 || l < 0) return -1;
        e->nt[i] = (uint8_t)((h << 4) | l);
    }
    /* owner = text between the 4th and 5th colon, if present. */
    if (nf == 6) {
        size_t olen = (size_t)(f[5] - f[4] - 1);
        if (olen > 0 && olen < SC_SAM_NAME_MAX) memcpy(e->owner, f[4], olen);
    }
    if (!e->owner[0]) memcpy(e->owner, e->user, strlen(e->user) + 1);
    return 0;
}

typedef struct { char *p; size_t len, cap; } sbuf;

static int sb_add(sbuf *b, const char *s, size_t n) {
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 256;
        while (nc < b->len + n + 1) nc *= 2;
        char *np = realloc(b->p, nc);
        if (!np) return -1;
        b->p = np; b->cap = nc;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
    return 0;
}

/* Iterate lines of text; callback decides. mode 0 = set_user, 1 = remove. */
static char *sam_rewrite(const char *text, const char *owner, const char *name,
                         const char *const *aliases, size_t naliases,
                         const uint8_t nt[16], int *removed) {
    sbuf out = {0};
    int rm = 0;
    if (!text) text = "";
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t ll = nl ? (size_t)(nl - p) : strlen(p);
        char line[1024];
        if (ll >= sizeof(line)) { /* absurd line: drop */
            p += ll + (nl ? 1 : 0);
            continue;
        }
        memcpy(line, p, ll);
        line[ll] = '\0';
        p += ll + (nl ? 1 : 0);
        size_t tl = ll;
        while (tl && line[tl - 1] == '\r') line[--tl] = '\0';
        if (tl == 0) continue;

        int keep = 1;
        if (line[0] == '#') {
            keep = 1;
        } else {
            sc_sam_entry e;
            if (sc_sam_parse_line(line, &e) != 0) {
                keep = 0;                       /* malformed: drop */
            } else if (owner) {                 /* set_user */
                if (strcasecmp(e.owner, owner) == 0) keep = 0;
                for (size_t i = 0; keep && i < naliases; i++)
                    if (strcmp(e.user, aliases[i]) == 0) keep = 0;
                if (!keep) rm++;
            } else if (name) {                  /* remove */
                if (strcasecmp(e.owner, name) == 0 || strcasecmp(e.user, name) == 0) {
                    keep = 0; rm++;
                }
            }
        }
        if (keep && (sb_add(&out, line, tl) || sb_add(&out, "\n", 1))) { free(out.p); return NULL; }
    }

    if (owner) {
        for (size_t i = 0; i < naliases; i++) {
            int dup = 0;
            for (size_t j = 0; j < i; j++) if (strcmp(aliases[i], aliases[j]) == 0) dup = 1;
            if (dup || !sc_sam_name_ok(aliases[i])) continue;
            char line[2 * SC_SAM_NAME_MAX + 64];
            int n = sc_sam_format_line(aliases[i], owner, nt, line, sizeof(line));
            if (n < 0) continue;
            if (sb_add(&out, line, (size_t)n) || sb_add(&out, "\n", 1)) { free(out.p); return NULL; }
        }
    }
    if (removed) *removed = rm;
    if (!out.p) { out.p = strdup(""); }
    return out.p;
}

char *sc_sam_text_set_user(const char *text, const char *owner,
                           const char *const *aliases, size_t naliases,
                           const uint8_t nt[16]) {
    if (!sc_sam_name_ok(owner) || !nt || (naliases && !aliases)) return NULL;
    return sam_rewrite(text, owner, NULL, aliases, naliases, nt, NULL);
}

char *sc_sam_text_remove(const char *text, const char *name, int *removed) {
    if (!name || !*name) return NULL;
    return sam_rewrite(text, NULL, name, NULL, 0, NULL, removed);
}

size_t sc_sam_text_count(const char *text) {
    size_t n = 0;
    if (!text) return 0;
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t ll = nl ? (size_t)(nl - p) : strlen(p);
        char line[1024];
        if (ll < sizeof(line)) {
            memcpy(line, p, ll);
            line[ll] = '\0';
            sc_sam_entry e;
            if (sc_sam_parse_line(line, &e) == 0) n++;
        }
        p += ll + (nl ? 1 : 0);
    }
    return n;
}

/* ── SAM files ───────────────────────────────────────────────────────────── */

static char *read_file(const char *path, int *err) {
    *err = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) { *err = errno; return NULL; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > (4 << 20)) {
        close(fd);
        *err = EINVAL;
        return NULL;
    }
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); *err = ENOMEM; return NULL; }
    size_t got = 0;
    while (got < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + got, (size_t)st.st_size - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    buf[got] = '\0';
    return buf;
}

int sc_sam_file_check(const char *path, size_t *count) {
    if (count) *count = 0;
    struct stat st;
    if (!path || lstat(path, &st) != 0) return -1;
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid()) return -2;
    if (st.st_mode & 077) (void)chmod(path, 0600);
    int err;
    char *text = read_file(path, &err);
    if (!text) return -1;
    if (count) *count = sc_sam_text_count(text);
    free(text);
    return 0;
}

static int ensure_parent_dir(const char *path) {
    char dir[1024];
    size_t n = strlen(path);
    if (n >= sizeof(dir)) return -1;
    memcpy(dir, path, n + 1);
    char *slash = strrchr(dir, '/');
    if (!slash || slash == dir) return 0;
    *slash = '\0';
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* Lock, read-modify-write atomically. mode 0 set_user, 1 remove. */
static int sam_file_update(const char *path, int mode, const char *owner,
                           const char *name, const char *const *aliases,
                           size_t naliases, const uint8_t nt[16]) {
    if (!path || !*path) return -1;
    if (ensure_parent_dir(path) != 0) return -1;

    char lockpath[1100];
    snprintf(lockpath, sizeof(lockpath), "%s.lock", path);
    int lfd = open(lockpath, O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    if (lfd < 0) return -1;
    if (flock(lfd, LOCK_EX) != 0) { close(lfd); return -1; }

    int result = -1;
    char *old = NULL, *neu = NULL;
    int err = 0;

    struct stat st;
    if (lstat(path, &st) == 0) {
        if (!S_ISREG(st.st_mode) || st.st_uid != geteuid()) goto done;
        old = read_file(path, &err);
        if (!old) goto done;
    } else if (errno != ENOENT) {
        goto done;
    }

    int removed = 0;
    neu = (mode == 0) ? sc_sam_text_set_user(old, owner, aliases, naliases, nt)
                      : sc_sam_text_remove(old, name, &removed);
    if (!neu) goto done;

    if (old && strcmp(old, neu) == 0) { result = 0; goto done; }
    if (!old && mode == 1) { result = 0; goto done; }

    char tmp[1100];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) goto done;
    size_t len = strlen(neu), off = 0;
    int okw = 1;
    while (off < len) {
        ssize_t w = write(fd, neu + off, len - off);
        if (w <= 0) { okw = 0; break; }
        off += (size_t)w;
    }
    if (okw && fsync(fd) != 0) okw = 0;
    close(fd);
    if (!okw || rename(tmp, path) != 0) { unlink(tmp); goto done; }
    result = (mode == 0) ? 1 : removed;

done:
    free(old);
    free(neu);
    flock(lfd, LOCK_UN);
    close(lfd);
    return result;
}

int sc_sam_file_set_user(const char *path, const char *owner,
                         const char *const *aliases, size_t naliases,
                         const uint8_t nt[16]) {
    if (!sc_sam_name_ok(owner) || !nt || (naliases && !aliases)) return -1;
    return sam_file_update(path, 0, owner, NULL, aliases, naliases, nt);
}

int sc_sam_file_remove(const char *path, const char *name) {
    if (!name || !*name) return -1;
    return sam_file_update(path, 1, NULL, name, NULL, 0, NULL);
}

/* ── Lockout tracker ─────────────────────────────────────────────────────── */

#define LK_MAXTS   32
#define LK_MAXKEYS 4096
#define LK_DECAY   86400
#define LK_KEYLEN  112

typedef struct {
    char   key[LK_KEYLEN];
    time_t ts[LK_MAXTS];
    int    nts;
    time_t locked_until;
    int    strikes;
} lk_entry;

struct sc_lockout {
    int threshold, window, base, dbl;
    lk_entry *e;
    size_t n, cap;
};

sc_lockout *sc_lockout_new(int threshold, int window_sec, int base_lock_sec,
                           int double_on_repeat) {
    sc_lockout *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->threshold = threshold < 1 ? 1 : (threshold > LK_MAXTS ? LK_MAXTS : threshold);
    t->window    = window_sec < 1 ? 1 : window_sec;
    t->base      = base_lock_sec < 1 ? 1 : base_lock_sec;
    t->dbl       = double_on_repeat ? 1 : 0;
    return t;
}

void sc_lockout_free(sc_lockout *t) {
    if (!t) return;
    free(t->e);
    free(t);
}

static lk_entry *lk_find(sc_lockout *t, const char *key) {
    for (size_t i = 0; i < t->n; i++)
        if (strncmp(t->e[i].key, key, LK_KEYLEN - 1) == 0) return &t->e[i];
    return NULL;
}

static void lk_remove_at(sc_lockout *t, size_t i) {
    t->e[i] = t->e[t->n - 1];
    t->n--;
}

static void lk_expire_ts(sc_lockout *t, lk_entry *e, time_t now) {
    int j = 0;
    for (int i = 0; i < e->nts; i++)
        if (now - e->ts[i] < t->window) e->ts[j++] = e->ts[i];
    e->nts = j;
}

static lk_entry *lk_get(sc_lockout *t, const char *key, time_t now) {
    lk_entry *e = lk_find(t, key);
    if (e) return e;
    if (t->n >= LK_MAXKEYS) {
        for (size_t i = 0; i < t->n;) {
            lk_entry *x = &t->e[i];
            lk_expire_ts(t, x, now);
            if (x->nts == 0 && x->locked_until <= now &&
                (x->strikes == 0 || now - x->locked_until > LK_DECAY))
                lk_remove_at(t, i);
            else
                i++;
        }
        if (t->n >= LK_MAXKEYS) lk_remove_at(t, 0);
    }
    if (t->n == t->cap) {
        size_t nc = t->cap ? t->cap * 2 : 16;
        lk_entry *ne = realloc(t->e, nc * sizeof(lk_entry));
        if (!ne) return NULL;
        t->e = ne; t->cap = nc;
    }
    e = &t->e[t->n++];
    memset(e, 0, sizeof(*e));
    snprintf(e->key, sizeof(e->key), "%s", key);
    return e;
}

int sc_lockout_remaining(sc_lockout *t, const char *key, time_t now) {
    if (!t || !key) return 0;
    lk_entry *e = lk_find(t, key);
    if (!e || e->locked_until <= now) return 0;
    return (int)(e->locked_until - now);
}

int sc_lockout_fail(sc_lockout *t, const char *key, time_t now) {
    if (!t || !key || !*key) return 0;
    lk_entry *e = lk_get(t, key, now);
    if (!e) return 0;
    if (e->locked_until > now) return 0;
    if (e->strikes && now - e->locked_until > LK_DECAY) e->strikes = 0;
    lk_expire_ts(t, e, now);
    if (e->nts == LK_MAXTS) {
        memmove(e->ts, e->ts + 1, (LK_MAXTS - 1) * sizeof(time_t));
        e->nts--;
    }
    e->ts[e->nts++] = now;
    if (e->nts < t->threshold) return 0;

    e->strikes++;
    long dur = t->base;
    if (t->dbl)
        for (int i = 1; i < e->strikes && dur < LK_DECAY; i++) dur *= 2;
    if (dur > LK_DECAY) dur = LK_DECAY;
    e->locked_until = now + (time_t)dur;
    e->nts = 0;
    return (int)dur;
}

void sc_lockout_reset(sc_lockout *t, const char *key) {
    if (!t || !key) return;
    for (size_t i = 0; i < t->n; i++)
        if (strncmp(t->e[i].key, key, LK_KEYLEN - 1) == 0) { lk_remove_at(t, i); return; }
}

int sc_lockout_count(sc_lockout *t, const char *key, time_t now) {
    if (!t || !key) return 0;
    lk_entry *e = lk_find(t, key);
    if (!e) return 0;
    lk_expire_ts(t, e, now);
    return e->nts;
}

/* ── Audit log ───────────────────────────────────────────────────────────── */

int sc_audit_append(const char *path, const char *line, long max_bytes) {
    if (!path || !line) return -1;
    struct stat st;
    if (max_bytes > 0 && stat(path, &st) == 0 && st.st_size >= max_bytes) {
        char old[1100];
        snprintf(old, sizeof(old), "%s.1", path);
        (void)rename(path, old);
    }
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    size_t ll = strlen(line);
    char *buf = malloc(ll + 2);
    if (!buf) { close(fd); return -1; }
    memcpy(buf, line, ll);
    buf[ll] = '\n';
    ssize_t w = write(fd, buf, ll + 1);
    free(buf);
    close(fd);
    return (w == (ssize_t)(ll + 1)) ? 0 : -1;
}
