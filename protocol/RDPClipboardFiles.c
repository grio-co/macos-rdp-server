#include "protocol/RDPClipboardFiles.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>

#define PATH_MAX_GUESS          1024   /* == macOS PATH_MAX; keeps recursion frames small */
#define RDP_FILESET_MAX_ENTRIES 200000
#define RDP_FILESET_MAX_DEPTH   48
#define HUGE_THRESHOLD          (2ULL * 1024 * 1024 * 1024)

/* ══ Mac -> Windows ═══════════════════════════════════════════════════════ */

struct RDPFileSet {
    int              refs;
    pthread_mutex_t  mu;
    bool             huge;
    char           **tops;
    size_t           nTops;
    bool             built, buildOk;
    RDPFileDesc     *descs;
    char           **paths;      /* absolute path per descriptor */
    uint32_t         n, cap;
    uint32_t         skipped;    /* entries left out (name too long / >=2GB w/o huge / limit) */
    int              fd;         /* single-entry fd cache */
    int64_t          fdIndex;
};

RDPFileSet *rdp_fileset_create(const char *const *paths, size_t n, bool huge) {
    RDPFileSet *s = (RDPFileSet *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->refs = 1;
    s->huge = huge;
    s->fd = -1;
    s->fdIndex = -1;
    pthread_mutex_init(&s->mu, NULL);
    s->tops = (char **)calloc(n ? n : 1, sizeof(char *));
    if (!s->tops) { free(s); return NULL; }
    for (size_t i = 0; i < n; i++) {
        s->tops[i] = strdup(paths[i]);
        if (!s->tops[i]) { s->nTops = i; rdp_fileset_release(s); return NULL; }
    }
    s->nTops = n;
    return s;
}

RDPFileSet *rdp_fileset_retain(RDPFileSet *s) {
    if (s) __atomic_add_fetch(&s->refs, 1, __ATOMIC_RELAXED);
    return s;
}

void rdp_fileset_release(RDPFileSet *s) {
    if (!s) return;
    if (__atomic_sub_fetch(&s->refs, 1, __ATOMIC_ACQ_REL) != 0) return;
    if (s->fd >= 0) close(s->fd);
    for (size_t i = 0; i < s->nTops; i++) free(s->tops[i]);
    free(s->tops);
    for (uint32_t i = 0; i < s->n; i++) { free(s->descs[i].name); free(s->paths[i]); }
    free(s->descs);
    free(s->paths);
    pthread_mutex_destroy(&s->mu);
    free(s);
}

void rdp_fileset_set_huge(RDPFileSet *s, bool huge) {
    if (!s) return;
    pthread_mutex_lock(&s->mu);
    if (!s->built) s->huge = huge;
    pthread_mutex_unlock(&s->mu);
}

size_t rdp_fileset_top_count(const RDPFileSet *s) { return s ? s->nTops : 0; }

static bool fs_add(RDPFileSet *s, const char *abs, const char *rel, const struct stat *st, bool isDir) {
    uint16_t probe[RDP_FD_NAME_MAX_UNITS + 1];
    if (rdp_utf8_to_utf16(rel, probe, RDP_FD_NAME_MAX_UNITS + 1) == (size_t)-1) { s->skipped++; return false; }
    if (!isDir && !s->huge && (uint64_t)st->st_size >= HUGE_THRESHOLD) { s->skipped++; return false; }
    if (s->n >= RDP_FILESET_MAX_ENTRIES) { s->skipped++; return false; }
    if (s->n == s->cap) {
        uint32_t nc = s->cap ? s->cap * 2 : 64;
        RDPFileDesc *nd = (RDPFileDesc *)realloc(s->descs, nc * sizeof(RDPFileDesc));
        if (!nd) return false;
        s->descs = nd;
        char **np = (char **)realloc(s->paths, nc * sizeof(char *));
        if (!np) return false;
        s->paths = np;
        s->cap = nc;
    }
    RDPFileDesc *d = &s->descs[s->n];
    memset(d, 0, sizeof(*d));
    d->name = strdup(rel);
    char *ap = strdup(abs);
    if (!d->name || !ap) { free(d->name); free(ap); return false; }
    d->flags = RDP_FD_ATTRIBUTES | RDP_FD_CREATETIME | RDP_FD_WRITESTIME | RDP_FD_PROGRESSUI;
    d->attrs = isDir ? RDP_FILE_ATTRIBUTE_DIRECTORY : RDP_FILE_ATTRIBUTE_NORMAL;
    if (!(st->st_mode & S_IWUSR)) d->attrs |= RDP_FILE_ATTRIBUTE_READONLY;
    d->creationTime = rdp_filetime_from_unix(st->st_birthtimespec.tv_sec, st->st_birthtimespec.tv_nsec);
    d->writeTime    = rdp_filetime_from_unix(st->st_mtimespec.tv_sec, st->st_mtimespec.tv_nsec);
    if (!isDir) { d->flags |= RDP_FD_FILESIZE; d->size = (uint64_t)st->st_size; }
    s->paths[s->n] = ap;
    s->n++;
    return true;
}

static int cmp_names(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static void fs_walk(RDPFileSet *s, const char *absDir, const char *relDir, int depth) {
    if (depth > RDP_FILESET_MAX_DEPTH) { s->skipped++; return; }
    DIR *dir = opendir(absDir);
    if (!dir) return;
    char **names = NULL;
    size_t nn = 0, cap = 0;
    struct dirent *e;
    while ((e = readdir(dir))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (nn == cap) {
            size_t nc = cap ? cap * 2 : 32;
            char **t = (char **)realloc(names, nc * sizeof(char *));
            if (!t) break;
            names = t; cap = nc;
        }
        names[nn] = strdup(e->d_name);
        if (names[nn]) nn++;
    }
    closedir(dir);
    if (nn > 1) qsort(names, nn, sizeof(char *), cmp_names);
    for (size_t i = 0; i < nn; i++) {
        char child[PATH_MAX_GUESS];
        char rel[PATH_MAX_GUESS];
        char comp[256];
        if (snprintf(child, sizeof(child), "%s/%s", absDir, names[i]) >= (int)sizeof(child)) { s->skipped++; continue; }
        size_t cl = strlen(names[i]);
        if (cl >= sizeof(comp)) cl = sizeof(comp) - 1;
        memcpy(comp, names[i], cl); comp[cl] = 0;
        for (char *c = comp; *c; c++) if (*c == '\\') *c = '_';
        if (snprintf(rel, sizeof(rel), "%s\\%s", relDir, comp) >= (int)sizeof(rel)) { s->skipped++; continue; }
        struct stat st;
        if (lstat(child, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) {
            if (stat(child, &st) != 0 || !S_ISREG(st.st_mode)) continue;   /* skip dir/dangling links: no loops */
        }
        if (S_ISDIR(st.st_mode)) {
            if (fs_add(s, child, rel, &st, true)) fs_walk(s, child, rel, depth + 1);
        } else if (S_ISREG(st.st_mode)) {
            fs_add(s, child, rel, &st, false);
        }
    }
    for (size_t i = 0; i < nn; i++) free(names[i]);
    free(names);
}

static void fs_build_locked(RDPFileSet *s) {
    if (s->built) return;
    s->built = true;
    for (size_t i = 0; i < s->nTops; i++) {
        const char *p = s->tops[i];
        size_t pl = strlen(p);
        while (pl > 1 && p[pl - 1] == '/') pl--;
        const char *base = p + pl;
        while (base > p && base[-1] != '/') base--;
        char name[256];
        size_t nl = (size_t)(p + pl - base);
        if (nl == 0 || nl >= sizeof(name)) { s->skipped++; continue; }
        memcpy(name, base, nl); name[nl] = 0;
        for (char *c = name; *c; c++) if (*c == '\\') *c = '_';
        struct stat st;
        if (stat(p, &st) != 0) { s->skipped++; continue; }
        if (S_ISDIR(st.st_mode)) {
            if (fs_add(s, p, name, &st, true)) fs_walk(s, p, name, 0);
        } else if (S_ISREG(st.st_mode)) {
            fs_add(s, p, name, &st, false);
        }
    }
    s->buildOk = s->n > 0;
}

bool rdp_fileset_descriptors(RDPFileSet *s, const RDPFileDesc **d, uint32_t *count) {
    if (!s) return false;
    pthread_mutex_lock(&s->mu);
    fs_build_locked(s);
    bool ok = s->buildOk;
    if (ok) { *d = s->descs; *count = s->n; }
    pthread_mutex_unlock(&s->mu);
    return ok;
}

bool rdp_fileset_serialize(RDPFileSet *s, uint8_t **out, size_t *outLen) {
    const RDPFileDesc *d; uint32_t n;
    if (!rdp_fileset_descriptors(s, &d, &n)) return false;
    return rdp_filelist_serialize(d, n, out, outLen);
}

bool rdp_fileset_size(RDPFileSet *s, uint32_t index, uint64_t *size) {
    const RDPFileDesc *d; uint32_t n;
    if (!rdp_fileset_descriptors(s, &d, &n) || index >= n) return false;
    if (d[index].attrs & RDP_FILE_ATTRIBUTE_DIRECTORY) { *size = 0; return true; }
    struct stat st;
    if (stat(s->paths[index], &st) == 0 && S_ISREG(st.st_mode)) *size = (uint64_t)st.st_size;
    else *size = d[index].size;
    return true;
}

ssize_t rdp_fileset_read(RDPFileSet *s, uint32_t index, uint64_t pos, uint8_t *buf, size_t len) {
    const RDPFileDesc *d; uint32_t n;
    if (!rdp_fileset_descriptors(s, &d, &n) || index >= n) return -1;
    if (d[index].attrs & RDP_FILE_ATTRIBUTE_DIRECTORY) return -1;
    pthread_mutex_lock(&s->mu);
    if (s->fdIndex != (int64_t)index) {
        if (s->fd >= 0) close(s->fd);
        s->fd = open(s->paths[index], O_RDONLY | O_CLOEXEC);
        s->fdIndex = s->fd >= 0 ? (int64_t)index : -1;
    }
    int fd = s->fd;
    ssize_t total = 0;
    if (fd < 0) { pthread_mutex_unlock(&s->mu); return -1; }
    while ((size_t)total < len) {
        ssize_t r = pread(fd, buf + total, len - (size_t)total, (off_t)(pos + (uint64_t)total));
        if (r < 0) { if (errno == EINTR) continue; total = -1; break; }
        if (r == 0) break;
        total += r;
    }
    pthread_mutex_unlock(&s->mu);
    return total;
}

/* ══ Windows -> Mac ═══════════════════════════════════════════════════════ */

bool rdp_clipfiles_safe_component(const char *src, size_t len, char *dst, size_t cap) {
    if (!src || !dst || cap < 2) return false;
    size_t l = 0;
    while (l < len && src[l]) l++;
    size_t o = l;
    if (o > 255 || o >= cap) {
        o = cap - 1 < 255 ? cap - 1 : 255;
        /* truncate on a UTF-8 character boundary */
        while (o > 0 && ((unsigned char)src[o] & 0xC0) == 0x80) o--;
    }
    for (size_t i = 0; i < o; i++) dst[i] = src[i] == '/' ? '_' : src[i];
    dst[o] = 0;
    if (o == 0 || !strcmp(dst, ".") || !strcmp(dst, "..")) return false;
    return true;
}

uint32_t rdp_clipfiles_top_entries(const RDPFileDesc *d, uint32_t n, uint32_t *idx, uint32_t cap) {
    uint32_t cnt = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (!d[i].name || !d[i].name[0] || strchr(d[i].name, '\\')) continue;
        if (idx && cnt < cap) idx[cnt] = i;
        cnt++;
    }
    return cnt;
}

static bool mkdir_p(const char *path) {
    char tmp[PATH_MAX_GUESS];
    size_t l = strlen(path);
    if (l >= sizeof(tmp)) return false;
    memcpy(tmp, path, l + 1);
    for (size_t i = 1; i < l; i++) {
        if (tmp[i] != '/') continue;
        tmp[i] = 0;
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return false;
        tmp[i] = '/';
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return false;
    return true;
}

/* Build <root>/<component>/<component>... from a backslash relative path. */
static bool local_path(const char *root, const char *rel, char *out, size_t cap) {
    size_t o = (size_t)snprintf(out, cap, "%s", root);
    if (o >= cap) return false;
    const char *p = rel;
    while (*p) {
        const char *e = strchr(p, '\\');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        char comp[256];
        if (l == 0) { p = e ? e + 1 : p + l; continue; }          /* tolerate "a\\\\b" */
        if (!rdp_clipfiles_safe_component(p, l, comp, sizeof(comp))) return false;
        int w = snprintf(out + o, cap - o, "/%s", comp);
        if (w < 0 || (size_t)w >= cap - o) return false;
        o += (size_t)w;
        p = e ? e + 1 : p + l;
    }
    return true;
}

static void apply_mtime(int fd, const char *path, const RDPFileDesc *d) {
    if (!(d->flags & RDP_FD_WRITESTIME) || !d->writeTime) return;
    int64_t sec; long nsec;
    if (!rdp_filetime_to_unix(d->writeTime, &sec, &nsec)) return;
    struct timespec ts[2] = { { .tv_sec = 0, .tv_nsec = UTIME_OMIT },
                              { .tv_sec = (time_t)sec, .tv_nsec = nsec } };
    if (fd >= 0) futimens(fd, ts);
    else utimensat(AT_FDCWD, path, ts, 0);
}

static bool download_file(const RDPFileDesc *d, uint32_t index, const char *path,
                          RDPFileFetchFn fetch, void *user, uint8_t *buf,
                          const volatile int *cancel, const char **err) {
    uint64_t size = 0;
    if (d->flags & RDP_FD_FILESIZE) size = d->size;
    else if (!fetch(user, index, true, 0, 8, NULL, NULL, &size)) { *err = "size request failed"; return false; }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) { *err = "cannot create file"; return false; }
    uint64_t pos = 0;
    bool ok = true;
    while (pos < size) {
        if (cancel && *cancel) { *err = "cancelled"; ok = false; break; }
        uint32_t want = (uint32_t)((size - pos) < RDP_CLIPFILES_CHUNK ? (size - pos) : RDP_CLIPFILES_CHUNK);
        uint32_t got = 0;
        if (!fetch(user, index, false, pos, want, buf, &got, NULL) || got == 0) {
            *err = "range request failed"; ok = false; break;
        }
        if (got > want) got = want;
        size_t w = 0;
        while (w < got) {
            ssize_t r = write(fd, buf + w, got - w);
            if (r < 0) { if (errno == EINTR) continue; *err = "write failed"; ok = false; break; }
            w += (size_t)r;
        }
        if (!ok) break;
        pos += got;
    }
    if (ok) apply_mtime(fd, path, d);
    close(fd);
    if (!ok) unlink(path);
    return ok;
}

char *rdp_clipfiles_download(const RDPFileDesc *d, uint32_t n, uint32_t topIndex,
                             const char *destRoot, RDPFileFetchFn fetch, void *user,
                             const volatile int *cancel, const char **err) {
    static const char *dummy;
    if (!err) err = &dummy;
    *err = NULL;
    if (!d || topIndex >= n || !destRoot || !fetch || !d[topIndex].name || strchr(d[topIndex].name, '\\')) {
        *err = "bad arguments"; return NULL;
    }
    if (!mkdir_p(destRoot)) { *err = "cannot create destination"; return NULL; }

    char topPath[PATH_MAX_GUESS];
    if (!local_path(destRoot, d[topIndex].name, topPath, sizeof(topPath))) { *err = "unsafe name"; return NULL; }

    uint8_t *buf = (uint8_t *)malloc(RDP_CLIPFILES_CHUNK);
    if (!buf) { *err = "out of memory"; return NULL; }
    bool ok = true;
    bool isDir = (d[topIndex].attrs & RDP_FILE_ATTRIBUTE_DIRECTORY) != 0;

    if (!isDir) {
        ok = download_file(&d[topIndex], topIndex, topPath, fetch, user, buf, cancel, err);
    } else {
        ok = mkdir_p(topPath);
        if (!ok) *err = "cannot create folder";
        size_t pl = strlen(d[topIndex].name);
        for (uint32_t j = 0; ok && j < n; j++) {
            if (j == topIndex || !d[j].name) continue;
            if (strncmp(d[j].name, d[topIndex].name, pl) != 0 || d[j].name[pl] != '\\') continue;
            char p[PATH_MAX_GUESS];
            if (!local_path(destRoot, d[j].name, p, sizeof(p))) { *err = "unsafe name"; ok = false; break; }
            if (d[j].attrs & RDP_FILE_ATTRIBUTE_DIRECTORY) {
                if (!mkdir_p(p)) { *err = "cannot create folder"; ok = false; }
            } else {
                /* parent might be absent from the list */
                char parent[PATH_MAX_GUESS];
                snprintf(parent, sizeof(parent), "%s", p);
                char *slash = strrchr(parent, '/');
                if (slash) { *slash = 0; mkdir_p(parent); }
                ok = download_file(&d[j], j, p, fetch, user, buf, cancel, err);
            }
        }
        /* Folder mtimes last: creating children bumps them. */
        if (ok) {
            for (uint32_t j = 0; j < n; j++) {
                if (!d[j].name || !(d[j].attrs & RDP_FILE_ATTRIBUTE_DIRECTORY)) continue;
                size_t l = strlen(d[j].name);
                if (j != topIndex && !(l > pl && strncmp(d[j].name, d[topIndex].name, pl) == 0 && d[j].name[pl] == '\\')) continue;
                char p[PATH_MAX_GUESS];
                if (local_path(destRoot, d[j].name, p, sizeof(p))) apply_mtime(-1, p, &d[j]);
            }
        }
    }
    free(buf);
    if (!ok) return NULL;
    return strdup(topPath);
}
