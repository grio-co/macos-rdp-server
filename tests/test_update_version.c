/* Unit test for daemon/UpdateVersion.h (updater downgrade / same-version guard). */
#include <stdio.h>
#include "daemon/UpdateVersion.h"

static int fails;
#define CMP(a, b, want) do { int g = update_version_compare(a, b); \
    if (g != (want)) { printf("FAIL cmp(%s,%s)=%d want %d\n", a, b, g, want); fails++; } } while (0)

int main(void) {
    CMP("v0.1.7", "v0.1.7", 0);
    CMP("v0.1.7", "0.1.7", 0);
    CMP("v0.1.7", "v0.1.7.0", 0);
    CMP("v0.1.6", "v0.1.7", -1);
    CMP("v0.1.8", "v0.1.7", 1);
    CMP("v0.1.10", "v0.1.9", 1);      /* numeric, not lexical */
    CMP("v0.2.0", "v0.1.99", 1);
    CMP("v1.0.0", "v0.9.9", 1);
    CMP("v0.1", "v0.1.1", -1);
    CMP("v0.1.7-rc1", "v0.1.6", -2);  /* pre-release rejected */
    CMP("8571732", "v0.1.6", -2);     /* git short SHA is not a version */
    CMP("dev-20260101000000", "v0.1.6", -2);
    CMP("v0.1.6", "", -2);
    CMP("v1.2.3.4.5.6.7.8.9", "v1.0.0", -2);
    if (fails) return 1;
    puts("test_update_version: ok");
    return 0;
}
