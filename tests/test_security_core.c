/* Standalone unit tests for daemon/SecurityCore.c (NT hash, SAM text/file ops,
 * lockout tracker, audit log rotation). Temp files only — never touches the
 * real ~/.macos-rdp/nla.sam.
 *
 *   clang -std=c11 -Wall -Wextra -I. -o /tmp/test_security_core \
 *         tests/test_security_core.c daemon/SecurityCore.c && /tmp/test_security_core
 */
#include "daemon/SecurityCore.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_fail = 0, g_run = 0;
#define CHECK(cond) do { g_run++; if (!(cond)) { g_fail++; \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static void hexof(const uint8_t *b, size_t n, char *out) { sc_hex_upper(b, n, out); }

static void test_hash(void) {
    uint8_t h[16]; char hex[33];
    sc_md4((const uint8_t *)"", 0, h); hexof(h, 16, hex);
    CHECK(strcmp(hex, "31D6CFE0D16AE931B73C59D7E0C089C0") == 0);
    sc_md4((const uint8_t *)"abc", 3, h); hexof(h, 16, hex);
    CHECK(strcmp(hex, "A448017AAF21D8525FC10AE87AA6729D") == 0);
    const char *m = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
    sc_md4((const uint8_t *)m, strlen(m), h); hexof(h, 16, hex);
    CHECK(strcmp(hex, "E33B4DDC9C38F2199C3E7B164FCC0536") == 0);

    CHECK(sc_nt_hash_utf8("password", h) == 0); hexof(h, 16, hex);
    CHECK(strcmp(hex, "8846F7EAEE8FB117AD06BDD830B7586C") == 0);
    CHECK(sc_nt_hash_utf8("", h) == 0); hexof(h, 16, hex);
    CHECK(strcmp(hex, "31D6CFE0D16AE931B73C59D7E0C089C0") == 0);
    /* Non-ASCII: "pässwörd" must hash the UTF-16LE form, not the UTF-8 bytes. */
    uint8_t a[16], b[16];
    CHECK(sc_nt_hash_utf8("p\xC3\xA4ssw\xC3\xB6rd", a) == 0);
    const uint8_t u16[] = {'p',0, 0xE4,0, 's',0, 's',0, 'w',0, 0xF6,0, 'r',0, 'd',0};
    sc_md4(u16, sizeof(u16), b);
    CHECK(memcmp(a, b, 16) == 0);
    /* Astral plane -> surrogate pair (U+1F600). */
    CHECK(sc_nt_hash_utf8("\xF0\x9F\x98\x80", a) == 0);
    const uint8_t sp[] = {0x3D,0xD8, 0x00,0xDE};
    sc_md4(sp, sizeof(sp), b);
    CHECK(memcmp(a, b, 16) == 0);
    /* Invalid UTF-8 is rejected. */
    CHECK(sc_nt_hash_utf8("\xC3", a) == -1);
    CHECK(sc_nt_hash_utf8("\xFF\xFE", a) == -1);
    CHECK(sc_nt_hash_utf8("\xC0\x80", a) == -1);
    CHECK(sc_nt_hash_utf8(NULL, a) == -1);
    /* Block boundary lengths (55,56,63,64,65 bytes) are self-consistent with the
     * generic path: hash of N 'a's as raw bytes must be deterministic and differ. */
    char buf[130]; memset(buf, 'a', sizeof(buf));
    char prev[33] = "";
    for (size_t n = 54; n <= 66; n++) {
        sc_md4((const uint8_t *)buf, n, h); hexof(h, 16, hex);
        CHECK(strcmp(hex, prev) != 0);
        strcpy(prev, hex);
    }
}

static const char *NT_PW = "8846F7EAEE8FB117AD06BDD830B7586C";

static void test_sam_text(void) {
    uint8_t nt[16]; sc_nt_hash_utf8("password", nt);
    char line[300];
    CHECK(sc_sam_format_line("grio", "grio", nt, line, sizeof(line)) > 0);
    char want[200]; snprintf(want, sizeof(want), "grio:::%s:grio:", NT_PW);
    CHECK(strcmp(line, want) == 0);

    /* Names with ':' / control chars / leading '#' / empty are refused. */
    CHECK(sc_sam_format_line("a:b", "grio", nt, line, sizeof(line)) == -1);
    CHECK(sc_sam_format_line("a\nb", "grio", nt, line, sizeof(line)) == -1);
    CHECK(sc_sam_format_line("#x", "grio", nt, line, sizeof(line)) == -1);
    CHECK(sc_sam_format_line("", "grio", nt, line, sizeof(line)) == -1);
    CHECK(sc_sam_format_line("grio", "grio", nt, line, 10) == -1);

    sc_sam_entry e;
    CHECK(sc_sam_parse_line(want, &e) == 0);
    CHECK(strcmp(e.user, "grio") == 0 && strcmp(e.owner, "grio") == 0);
    CHECK(memcmp(e.nt, nt, 16) == 0);
    /* WinPR-style hand-written line (no owner) and a lowercase hash. */
    CHECK(sc_sam_parse_line("bob:DOM::8846f7eaee8fb117ad06bdd830b7586c:::", &e) == 0);
    CHECK(strcmp(e.user, "bob") == 0 && strcmp(e.owner, "bob") == 0);
    CHECK(memcmp(e.nt, nt, 16) == 0);
    CHECK(sc_sam_parse_line("# comment", &e) == -1);
    CHECK(sc_sam_parse_line("", &e) == -1);
    CHECK(sc_sam_parse_line("bob:::SHORT:::", &e) == -1);
    CHECK(sc_sam_parse_line("bob:::ZZZZF7EAEE8FB117AD06BDD830B7586C:::", &e) == -1);
    CHECK(sc_sam_parse_line("nocolons", &e) == -1);

    /* set_user: aliases deduped, owner lines replaced, other users + comments kept. */
    const char *al1[] = {"grio", "Grioghar T", "grio", "Grio"};
    char *t1 = sc_sam_text_set_user("# my sam\nbob:::" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ":bob:\n", "grio", al1, 4, nt);
    CHECK(t1 != NULL);
    CHECK(sc_sam_text_count(t1) == 4);   /* bob + 3 distinct aliases */
    CHECK(strstr(t1, "# my sam") != NULL);
    CHECK(strstr(t1, "Grioghar T:::") != NULL);

    /* New hash replaces every previous alias of the same owner (even stale ones). */
    uint8_t nt2[16]; sc_nt_hash_utf8("newpass", nt2);
    const char *al2[] = {"grio"};
    char *t2 = sc_sam_text_set_user(t1, "GRIO", al2, 1, nt2);   /* owner case-insens. */
    CHECK(t2 && sc_sam_text_count(t2) == 2);                    /* bob + grio */
    CHECK(strstr(t2, NT_PW) == NULL);
    char hex2[33]; sc_hex_upper(nt2, 16, hex2);
    CHECK(strstr(t2, hex2) != NULL);

    /* remove by owner removes all aliases; by alias too; unknown name is a no-op. */
    int removed = -1;
    char *t3 = sc_sam_text_remove(t1, "grio", &removed);
    CHECK(t3 && removed == 3 && sc_sam_text_count(t3) == 1 && strstr(t3, "bob:::"));
    free(t3);
    t3 = sc_sam_text_remove(t1, "Grioghar T", &removed);
    CHECK(t3 && removed == 1 && sc_sam_text_count(t3) == 3);
    free(t3);
    t3 = sc_sam_text_remove(t1, "nobody", &removed);
    CHECK(t3 && removed == 0 && strcmp(t3, t1) == 0);
    free(t3);

    /* Malformed lines are dropped on rewrite (WinPR aborts lookups at them). */
    char *t4 = sc_sam_text_set_user("garbage line\n\r\nbob:::" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ":bob:\r\n", "grio", al2, 1, nt);
    CHECK(t4 && sc_sam_text_count(t4) == 2 && strstr(t4, "garbage") == NULL && strchr(t4, '\r') == NULL);
    free(t4);
    CHECK(sc_sam_text_set_user("", "bad:owner", al2, 1, nt) == NULL);
    free(t1); free(t2);
}

static void test_sam_file(void) {
    char dir[] = "/tmp/sc_test_XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char path[300]; snprintf(path, sizeof(path), "%s/sub/nla.sam", dir);
    size_t n = 99;
    CHECK(sc_sam_file_check(path, &n) == -1 && n == 0);

    uint8_t nt[16]; sc_nt_hash_utf8("password", nt);
    const char *al[] = {"grio", "Grio"};
    CHECK(sc_sam_file_set_user(path, "grio", al, 2, nt) == 1);      /* creates dir + file */
    struct stat st;
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    char sub[300]; snprintf(sub, sizeof(sub), "%s/sub", dir);
    CHECK(stat(sub, &st) == 0 && (st.st_mode & 0777) == 0700);
    CHECK(sc_sam_file_check(path, &n) == 0 && n == 2);
    CHECK(sc_sam_file_set_user(path, "grio", al, 2, nt) == 0);      /* unchanged */

    /* loosened mode is tightened */
    chmod(path, 0644);
    CHECK(sc_sam_file_check(path, &n) == 0);
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);

    const char *al2[] = {"bob"};
    CHECK(sc_sam_file_set_user(path, "bob", al2, 1, nt) == 1);
    CHECK(sc_sam_file_check(path, &n) == 0 && n == 3);
    CHECK(sc_sam_file_remove(path, "grio") == 2);
    CHECK(sc_sam_file_check(path, &n) == 0 && n == 1);
    CHECK(sc_sam_file_remove(path, "grio") == 0);
    CHECK(sc_sam_file_remove(path, "bob") == 1);
    CHECK(sc_sam_file_check(path, &n) == 0 && n == 0);

    /* no temp files left behind */
    char cmd[400]; snprintf(cmd, sizeof(cmd), "ls %s/sub | grep -c tmp > /dev/null", dir);
    CHECK(system(cmd) != 0);

    /* symlink refused */
    char link[300]; snprintf(link, sizeof(link), "%s/link.sam", dir);
    CHECK(symlink(path, link) == 0);
    CHECK(sc_sam_file_check(link, &n) == -2);
    CHECK(sc_sam_file_set_user(link, "grio", al, 2, nt) == -1);

    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    (void)system(cmd);
}

static void test_lockout(void) {
    sc_lockout *t = sc_lockout_new(5, 600, 900, 1);
    time_t T = 1000000;
    const char *k = "ip:10.0.0.5";
    for (int i = 0; i < 4; i++) CHECK(sc_lockout_fail(t, k, T + i) == 0);
    CHECK(sc_lockout_remaining(t, k, T + 5) == 0);
    CHECK(sc_lockout_count(t, k, T + 5) == 4);
    CHECK(sc_lockout_fail(t, k, T + 5) == 900);                       /* 5th triggers */
    CHECK(sc_lockout_remaining(t, k, T + 5) == 900);
    CHECK(sc_lockout_remaining(t, k, T + 5 + 899) == 1);
    CHECK(sc_lockout_remaining(t, k, T + 5 + 900) == 0);
    CHECK(sc_lockout_fail(t, k, T + 100) == 0);                       /* ignored while locked */
    CHECK(sc_lockout_remaining(t, "ip:10.0.0.6", T) == 0);            /* independent keys */

    /* Repeat offence doubles: 1800, then 3600. */
    time_t T2 = T + 2000;
    for (int i = 0; i < 4; i++) sc_lockout_fail(t, k, T2 + i);
    CHECK(sc_lockout_fail(t, k, T2 + 4) == 1800);
    time_t T3 = T2 + 5000;
    for (int i = 0; i < 4; i++) sc_lockout_fail(t, k, T3 + i);
    CHECK(sc_lockout_fail(t, k, T3 + 4) == 3600);

    /* Window: failures spread wider than 10 min never lock. */
    const char *w = "user:bob";
    int locked = 0;
    for (int i = 0; i < 20; i++) locked |= sc_lockout_fail(t, w, T + i * 200);
    CHECK(locked == 0);
    CHECK(sc_lockout_count(t, w, T + 19 * 200) <= 3);

    /* Success resets counters and repeat history. */
    const char *r = "ip:10.0.0.9";
    for (int i = 0; i < 4; i++) sc_lockout_fail(t, r, T + i);
    sc_lockout_reset(t, r);
    CHECK(sc_lockout_count(t, r, T + 5) == 0);
    for (int i = 0; i < 4; i++) CHECK(sc_lockout_fail(t, r, T + 10 + i) == 0);
    CHECK(sc_lockout_fail(t, r, T + 20) == 900);                      /* not doubled */
    sc_lockout_reset(t, r);
    for (int i = 0; i < 4; i++) sc_lockout_fail(t, r, T + 3000 + i);
    CHECK(sc_lockout_fail(t, r, T + 3010) == 900);

    /* Strikes decay after 24 h of good behaviour. */
    const char *d = "ip:10.0.0.7";
    for (int i = 0; i < 4; i++) sc_lockout_fail(t, d, T + i);
    CHECK(sc_lockout_fail(t, d, T + 4) == 900);
    time_t late = T + 4 + 900 + 86400 + 10;
    for (int i = 0; i < 4; i++) sc_lockout_fail(t, d, late + i);
    CHECK(sc_lockout_fail(t, d, late + 4) == 900);
    sc_lockout_free(t);

    /* No doubling mode, and threshold 1. */
    sc_lockout *n = sc_lockout_new(1, 60, 300, 0);
    CHECK(sc_lockout_fail(n, "a", 100) == 300);
    CHECK(sc_lockout_fail(n, "a", 500) == 300);
    sc_lockout_free(n);

    /* Table cap: thousands of distinct keys don't blow up and old entries age out. */
    sc_lockout *big = sc_lockout_new(5, 600, 900, 1);
    char key[32];
    for (int i = 0; i < 6000; i++) {
        snprintf(key, sizeof(key), "ip:%d", i);
        sc_lockout_fail(big, key, 5000 + i);
    }
    CHECK(sc_lockout_count(big, "ip:5999", 5000 + 5999) == 1);
    sc_lockout_free(big);
}

static long fsize(const char *p) { struct stat st; return stat(p, &st) == 0 ? (long)st.st_size : -1; }

static void test_audit(void) {
    char dir[] = "/tmp/sc_audit_XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char path[300], old[310];
    snprintf(path, sizeof(path), "%s/conn.log", dir);
    snprintf(old, sizeof(old), "%s.1", path);
    CHECK(sc_audit_append(path, "line one", 100) == 0);
    struct stat st;
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    for (int i = 0; i < 20; i++) CHECK(sc_audit_append(path, "0123456789 0123456789", 100) == 0);
    CHECK(fsize(old) > 0);              /* rotated at least once */
    CHECK(fsize(path) < 200);           /* current stays small */
    long before = fsize(old);
    for (int i = 0; i < 20; i++) sc_audit_append(path, "0123456789 0123456789", 100);
    char p2[320]; snprintf(p2, sizeof(p2), "%s.2", path);
    CHECK(access(p2, F_OK) != 0);       /* only one generation kept */
    CHECK(fsize(old) > 0 && before > 0);
    char cmd[400]; snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    (void)system(cmd);
}

int main(void) {
    test_hash();
    test_sam_text();
    test_sam_file();
    test_lockout();
    test_audit();
    printf("%d checks, %d failed\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
