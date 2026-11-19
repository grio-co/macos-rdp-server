/* Update signature check (daemon/UpdateVerify.m) against real binaries:
 * the Developer ID build passes; a tampered copy, an unsigned copy and a missing
 * file fail. RDP_TEST_DAEMON overrides the binary (default: build/release);
 * RDP_TEST_OTHER_SIGNED names a binary signed by any other identity (e.g. Apple
 * Development), which must fail. Skips when no daemon build exists. */
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include "daemon/UpdateVerify.h"

static int failures = 0, checks = 0;

static void expect(const char *label, const char *path, bool want) {
    const char *why = NULL;
    bool got = update_verify_signature(path, &why);
    checks++;
    if (got != want) {
        failures++;
        printf("FAIL %s: got %s (%s)\n", label, got ? "accept" : "reject", why ? why : "-");
    } else {
        printf("  ok %s: %s%s%s\n", label, got ? "accepted" : "rejected: ",
               got ? "" : why, "");
    }
}

static bool copy_file(const char *from, const char *to) {
    NSFileManager *fm = NSFileManager.defaultManager;
    [fm removeItemAtPath:@(to) error:NULL];
    return [fm copyItemAtPath:@(from) toPath:@(to) error:NULL];
}

int main(int argc, char **argv) {
    @autoreleasepool {
        const char *bin = getenv("RDP_TEST_DAEMON");
        NSString *root = [[@(argv[0]) stringByDeletingLastPathComponent]
                            stringByAppendingPathComponent:@"../.."];
        NSString *def = [root stringByAppendingPathComponent:@"build/release/macos-rdp-daemon"];
        if (!bin) bin = def.fileSystemRepresentation;
        if (access(bin, R_OK) != 0) {
            printf("skip: no daemon build at %s (run scripts/build-local.sh)\n", bin);
            return 0;
        }
        const char *tmp = getenv("TEST_TMP") ?: "/tmp";
        char tampered[1024], unsigned_[1024];
        snprintf(tampered, sizeof tampered, "%s/verify-tampered", tmp);
        snprintf(unsigned_, sizeof unsigned_, "%s/verify-unsigned", tmp);

        expect("Developer ID build", bin, true);

        if (copy_file(bin, tampered)) {          /* flip one byte inside __TEXT */
            FILE *f = fopen(tampered, "r+b");
            if (f && fseek(f, 0x4100, SEEK_SET) == 0) {
                int c = fgetc(f);
                fseek(f, 0x4100, SEEK_SET);
                fputc(c ^ 0xFF, f);
            }
            if (f) fclose(f);
            expect("tampered copy", tampered, false);
        }
        if (copy_file(bin, unsigned_)) {
            char cmd[1200];
            snprintf(cmd, sizeof cmd, "/usr/bin/codesign --remove-signature '%s'", unsigned_);
            if (system(cmd) == 0) expect("unsigned copy", unsigned_, false);
        }
        expect("missing file", "/nonexistent/macos-rdp-daemon", false);
        const char *other = getenv("RDP_TEST_OTHER_SIGNED");
        if (other) expect("other identity", other, false);

        unlink(tampered);
        unlink(unsigned_);
    }
    printf("%d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
