/* protocol/RDPDrivePath.c: URL <-> RDPDR path mapping, UTF-8 <-> UTF-16LE with
 * the NUL MS-RDPEFS PathLength counts, href encoding, XML escaping, dates. */
#include "protocol/RDPDrivePath.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

static bool path_is(const char *url, const char *want) {
    char out[64];
    return rdpdr_path_from_url(url, out, sizeof(out)) && strcmp(out, want) == 0;
}
static bool path_rejected(const char *url) {
    char out[64];
    return !rdpdr_path_from_url(url, out, sizeof(out)) && out[0] == '\0';
}

int main(void) {
    /* Root is "", everything else gets a leading backslash, none trailing. */
    CHECK(path_is("/", ""));
    CHECK(path_is("", ""));
    CHECK(path_is("//", ""));
    CHECK(path_is("/hello.txt", "\\hello.txt"));
    CHECK(path_is("/a/b/", "\\a\\b"));
    CHECK(path_is("//a///b", "\\a\\b"));
    CHECK(path_is("/New folder/x y.txt", "\\New folder\\x y.txt"));
    CHECK(path_is("/a/..b/c.", "\\a\\..b\\c."));
    CHECK(path_rejected("/.."));
    CHECK(path_rejected("/a/../b"));
    CHECK(path_rejected("/a/./b"));
    CHECK(path_rejected("/a\\b"));
    CHECK(path_rejected("/file.txt:stream"));
    {   /* Too long for the buffer: refused, not truncated. */
        char out[8];
        CHECK(!rdpdr_path_from_url("/abcdefgh", out, sizeof(out)));
        CHECK(rdpdr_path_from_url("/abcdef", out, sizeof(out)) && strcmp(out, "\\abcdef") == 0);
    }

    /* Percent-decoding. */
    {
        char s[64];
        strcpy(s, "/New%20folder/R%C3%A9sum%c3%a9.txt");
        CHECK(rdp_url_decode(s) && strcmp(s, "/New folder/R\xC3\xA9sum\xC3\xA9.txt") == 0);
        strcpy(s, "/a%2");   CHECK(!rdp_url_decode(s));
        strcpy(s, "/a%zz");  CHECK(!rdp_url_decode(s));
        strcpy(s, "/a%00b"); CHECK(!rdp_url_decode(s));
        strcpy(s, "/a+b");   CHECK(rdp_url_decode(s) && strcmp(s, "/a+b") == 0);
    }
    CHECK(strcmp(rdp_url_path_part("http://127.0.0.1:5000/a/b%20c"), "/a/b%20c") == 0);
    CHECK(strcmp(rdp_url_path_part("http://127.0.0.1:5000"), "") == 0);
    CHECK(strcmp(rdp_url_path_part("/plain/path"), "/plain/path") == 0);

    /* UTF-8 -> UTF-16LE, NUL included in the count. */
    {
        uint8_t w[32];
        CHECK(rdpdr_utf8_to_utf16le("", w, sizeof(w)) == 2 && w[0] == 0 && w[1] == 0);
        size_t n = rdpdr_utf8_to_utf16le("\\a", w, sizeof(w));
        CHECK(n == 6 && w[0] == '\\' && w[1] == 0 && w[2] == 'a' && w[3] == 0 && w[4] == 0 && w[5] == 0);
        n = rdpdr_utf8_to_utf16le("\xC3\xA9", w, sizeof(w));          /* U+00E9 */
        CHECK(n == 4 && w[0] == 0xE9 && w[1] == 0x00);
        n = rdpdr_utf8_to_utf16le("\xE2\x82\xAC", w, sizeof(w));      /* U+20AC */
        CHECK(n == 4 && w[0] == 0xAC && w[1] == 0x20);
        n = rdpdr_utf8_to_utf16le("\xF0\x9F\x98\x80", w, sizeof(w));  /* U+1F600 */
        CHECK(n == 6 && w[0] == 0x3D && w[1] == 0xD8 && w[2] == 0x00 && w[3] == 0xDE);
        CHECK(rdpdr_utf8_to_utf16le("\xC0\xAF", w, sizeof(w)) == 0);      /* overlong '/' */
        CHECK(rdpdr_utf8_to_utf16le("\xED\xA0\x80", w, sizeof(w)) == 0);  /* surrogate */
        CHECK(rdpdr_utf8_to_utf16le("\xC3", w, sizeof(w)) == 0);          /* truncated */
        CHECK(rdpdr_utf8_to_utf16le("abc", w, 7) == 0);                   /* no room for NUL */
        CHECK(rdpdr_utf8_to_utf16le("abc", w, 8) == 8);
    }

    /* UTF-16LE -> UTF-8, round trip, bad surrogates, early NUL. */
    {
        const char *samples[] = { "hello.txt", "R\xC3\xA9sum\xC3\xA9", "\xE2\x82\xAC 5",
                                  "\xF0\x9F\x98\x80.png", "" };
        for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
            uint8_t w[64]; char back[64];
            size_t n = rdpdr_utf8_to_utf16le(samples[i], w, sizeof(w));
            CHECK(n >= 2);
            CHECK(rdpdr_utf16le_to_utf8(w, n - 2, back, sizeof(back)) && strcmp(back, samples[i]) == 0);
            CHECK(rdpdr_utf16le_to_utf8(w, n, back, sizeof(back)) && strcmp(back, samples[i]) == 0);
        }
        char out[16];
        const uint8_t lone[] = { 0x00, 0xD8, 'x', 0 };            /* high surrogate, then 'x' */
        CHECK(rdpdr_utf16le_to_utf8(lone, sizeof(lone), out, sizeof(out)) &&
              strcmp(out, "\xEF\xBF\xBDx") == 0);
        const uint8_t odd[] = { 'a', 0, 'b' };                    /* odd byte count */
        CHECK(rdpdr_utf16le_to_utf8(odd, sizeof(odd), out, sizeof(out)) && strcmp(out, "a") == 0);
        const uint8_t nul[] = { 'a', 0, 0, 0, 'b', 0 };
        CHECK(rdpdr_utf16le_to_utf8(nul, sizeof(nul), out, sizeof(out)) && strcmp(out, "a") == 0);
        char tiny[3];
        const uint8_t abc[] = { 'a', 0, 'b', 0, 'c', 0 };
        CHECK(!rdpdr_utf16le_to_utf8(abc, sizeof(abc), tiny, sizeof(tiny)) && strcmp(tiny, "ab") == 0);
    }

    /* href encoding and XML escaping. */
    {
        char out[128];
        CHECK(rdp_url_path_encode("/New folder/R\xC3\xA9sum\xC3\xA9 #1&2.txt", out, sizeof(out)) &&
              strcmp(out, "/New%20folder/R%C3%A9sum%C3%A9%20%231%262.txt") == 0);
        CHECK(rdp_url_path_encode("/a-b_c.d~e", out, sizeof(out)) && strcmp(out, "/a-b_c.d~e") == 0);
        char small[4];
        CHECK(!rdp_url_path_encode("/ a", small, sizeof(small)) && strcmp(small, "/") == 0);
        CHECK(rdp_xml_escape("a&b<c>d\"e'f", out, sizeof(out)) &&
              strcmp(out, "a&amp;b&lt;c&gt;d&quot;e&apos;f") == 0);
        CHECK(rdp_xml_escape("R\xC3\xA9sum\xC3\xA9", out, sizeof(out)) && strcmp(out, "R\xC3\xA9sum\xC3\xA9") == 0);
        CHECK(!rdp_xml_escape("&&", small, sizeof(small)));
    }

    /* FILETIME -> HTTP date. */
    {
        char d[40];
        rdp_http_date_from_filetime(0, d, sizeof(d));
        CHECK(strcmp(d, "Thu, 01 Jan 1970 00:00:00 GMT") == 0);
        /* 2025-01-01 00:00:00 UTC = 1735689600 s after the Unix epoch. */
        rdp_http_date_from_filetime(116444736000000000ULL + 1735689600ULL * 10000000ULL, d, sizeof(d));
        CHECK(strcmp(d, "Wed, 01 Jan 2025 00:00:00 GMT") == 0);
        rdp_http_date_from_filetime(116444736000000000ULL + 951825600ULL * 10000000ULL + 9999999ULL, d, sizeof(d));
        CHECK(strcmp(d, "Tue, 29 Feb 2000 12:00:00 GMT") == 0);
        rdp_http_date_from_filetime(1, d, sizeof(d));              /* before 1970 */
        CHECK(strcmp(d, "Thu, 01 Jan 1970 00:00:00 GMT") == 0);
    }

    /* base64, both ways. */
    {
        char e[16];
        uint8_t d[16];
        const char *plain[] = { "", "f", "fo", "foo", "foob", "fooba", "foobar" };
        const char *coded[] = { "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy" };
        for (int i = 0; i < 7; i++) {
            size_t pl = strlen(plain[i]);
            CHECK(rdp_base64_encode((const uint8_t *)plain[i], pl, e, sizeof(e)) &&
                  strcmp(e, coded[i]) == 0);
            long n = rdp_base64_decode(coded[i], strlen(coded[i]), d, sizeof(d));
            CHECK(n == (long)pl && memcmp(d, plain[i], pl) == 0);
        }
        CHECK(!rdp_base64_encode((const uint8_t *)"foo", 3, e, 4) && e[0] == '\0');  /* NUL */
        CHECK(rdp_base64_decode("Zm8", 3, d, sizeof(d)) == 2 && memcmp(d, "fo", 2) == 0);
        CHECK(rdp_base64_decode("Zg", 2, d, sizeof(d)) == 1 && d[0] == 'f');
        CHECK(rdp_base64_decode("Z", 1, d, sizeof(d)) == -1);         /* 6 bits */
        CHECK(rdp_base64_decode("Zm9v!A==", 8, d, sizeof(d)) == -1);  /* bad char */
        CHECK(rdp_base64_decode("Zm=8", 4, d, sizeof(d)) == -1);      /* '=' inside */
        CHECK(rdp_base64_decode("Zg===", 5, d, sizeof(d)) == -1);     /* too much '=' */
        CHECK(rdp_base64_decode("Zm8==", 5, d, sizeof(d)) == -1);     /* not a group */
        CHECK(rdp_base64_decode("Zh==", 4, d, sizeof(d)) == -1);      /* stray bits */
        CHECK(rdp_base64_decode("Zm9v Zg==", 9, d, sizeof(d)) == -1); /* space */
        CHECK(rdp_base64_decode("Zm9vYmFy", 8, d, 5) == -1);          /* doesn't fit */
        uint8_t all[256];
        for (int i = 0; i < 256; i++) all[i] = (uint8_t)i;
        char big[400];
        uint8_t back[256];
        CHECK(rdp_base64_encode(all, sizeof(all), big, sizeof(big)));
        CHECK(rdp_base64_decode(big, strlen(big), back, sizeof(back)) == 256 &&
              memcmp(all, back, 256) == 0);
    }

    /* Basic authentication against the drive's user:password. */
    {
        const char *want = "macrdp:s3cret";
#define AUTH_OK(v) rdp_http_basic_auth_ok(v, strlen(v), want)
        CHECK(AUTH_OK("Basic bWFjcmRwOnMzY3JldA=="));
        CHECK(AUTH_OK("basic \t bWFjcmRwOnMzY3JldA=="));
        CHECK(AUTH_OK("BASIC bWFjcmRwOnMzY3JldA"));               /* padding left off */
        CHECK(!AUTH_OK("Basic bWFjcmRwOnMzY3JldB=="));            /* other password */
        CHECK(!AUTH_OK("Basic bWFjcmRwOnMzY3Jl"));                /* "macrdp:s3cre" */
        CHECK(!AUTH_OK("Basic bWFjcmRwOnMzY3JldHg="));            /* "macrdp:s3cretx" */
        CHECK(!AUTH_OK("Digest bWFjcmRwOnMzY3JldA=="));
        CHECK(!AUTH_OK("BasicbWFjcmRwOnMzY3JldA=="));
        CHECK(!AUTH_OK("Basic"));
        CHECK(!AUTH_OK("Basic "));
        CHECK(!AUTH_OK(""));
        CHECK(!rdp_http_basic_auth_ok("Basic Og==", 10, ""));    /* ":" vs nothing */
        CHECK(!rdp_http_basic_auth_ok("Basic bWFjcmRwOnMzY3JldA==", 26, NULL));
        CHECK(!rdp_http_basic_auth_ok(NULL, 0, want));
        /* Only len bytes count. */
        CHECK(rdp_http_basic_auth_ok("Basic bWFjcmRwOnMzY3JldA==XYZ", 26, want));
#undef AUTH_OK
    }

    printf(fails ? "test_drivepath: %d FAILED\n" : "test_drivepath: all passed\n", fails);
    return fails ? 1 : 0;
}
