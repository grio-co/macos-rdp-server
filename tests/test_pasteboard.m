/*
 * Verifies the NSPasteboard assumptions the clipboard design relies on, using a
 * PRIVATE pasteboard (pasteboardWithUniqueName) only — never the general one:
 *
 *   1. NSPasteboardItemDataProvider callbacks are delivered on the MAIN thread
 *      while the main run loop runs (so daemon/main.m must run it), even when the
 *      reader is another thread.
 *   2. A provider may block for a while (waiting for the RDP client) and the
 *      reader still gets the data.
 *   3. Fulfilling a promise does not bump changeCount (so lazy rendering cannot
 *      look like a new Mac copy to the poller), and the private origin marker
 *      type is visible in pb.types (the poller's loop guard).
 *   4. File-URL promises: one item per entry, URL read back.
 */
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>

static int g_fail = 0, g_pass = 0;
#define CHECK(cond) do { if (cond) g_pass++; else { g_fail++; \
    printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static NSPasteboardType const kMarker = @"com.macosrdp.clipboard-origin";

@interface Prov : NSObject <NSPasteboardItemDataProvider>
@property (atomic) int calls;
@property (atomic) BOOL allOnMain;
@property (nonatomic, strong) dispatch_semaphore_t gate;     /* released by "the RDP client" */
@end
@implementation Prov
- (void)pasteboard:(NSPasteboard *)pb item:(NSPasteboardItem *)item provideDataForType:(NSPasteboardType)type {
    self.calls++;
    if (![NSThread isMainThread]) self.allOnMain = NO;
    if ([type isEqualToString:NSPasteboardTypeHTML]) {
        /* block like a paste waiting on the client; the response arrives on ANOTHER thread */
        dispatch_semaphore_wait(self.gate, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
        [item setData:[@"<b>from windows</b>" dataUsingEncoding:NSUTF8StringEncoding] forType:type];
    } else if ([type isEqualToString:NSPasteboardTypeFileURL]) {
        [item setString:[NSURL fileURLWithPath:@"/tmp/macrdp-test-file.txt"].absoluteString forType:type];
    }
}
- (void)pasteboardFinishedWithDataProvider:(NSPasteboard *)pb {}
@end

int main(void) {
    @autoreleasepool {
        NSPasteboard *pb = [NSPasteboard pasteboardWithUniqueName];
        Prov *prov = [[Prov alloc] init];
        prov.allOnMain = YES;
        prov.gate = dispatch_semaphore_create(0);

        NSPasteboardItem *text = [[NSPasteboardItem alloc] init];
        [text setString:@"1" forType:kMarker];
        [text setString:@"eager text" forType:NSPasteboardTypeString];
        [text setDataProvider:prov forTypes:@[NSPasteboardTypeHTML]];
        NSPasteboardItem *f1 = [[NSPasteboardItem alloc] init];
        [f1 setString:@"1" forType:kMarker];
        [f1 setDataProvider:prov forTypes:@[NSPasteboardTypeFileURL]];
        [pb clearContents];
        BOOL wrote = [pb writeObjects:@[text, f1]];
        CHECK(wrote);
        NSInteger cc = pb.changeCount;
        CHECK([pb.types containsObject:kMarker]);
        CHECK([[pb stringForType:NSPasteboardTypeString] isEqualToString:@"eager text"]);
        CHECK(prov.calls == 0);                                    /* promises are lazy */

        /* A DIFFERENT PROCESS reads the private pasteboard by name, like Finder would
         * on Cmd+V: the pasteboard server then calls back into this process to
         * fulfil the promise. (An in-process reader short-circuits that and runs the
         * provider on the reader's own thread, so it cannot model the daemon.) */
        __block NSString *childOut = nil;
        __block BOOL done = NO;
        NSString *js = [NSString stringWithFormat:
            @"ObjC.import('AppKit');"
            @"var pb=$.NSPasteboard.pasteboardWithName('%@');"
            @"var h=pb.stringForType('public.html');"
            @"var u=pb.readObjectsForClassesOptions($([$.NSURL]),$({NSPasteboardURLReadingFileURLsOnlyKey:true}));"
            @"var path=(u && u.count>0)? ObjC.unwrap(u.objectAtIndex(0).path) : '';"
            @"console.log(ObjC.unwrap(h)+'|'+path);", pb.name];
        dispatch_queue_t reader = dispatch_queue_create("reader", DISPATCH_QUEUE_SERIAL);
        dispatch_async(reader, ^{
            NSTask *t = [[NSTask alloc] init];
            t.launchPath = @"/usr/bin/osascript";
            t.arguments = @[@"-l", @"JavaScript", @"-e", js];
            NSPipe *p = [NSPipe pipe];
            t.standardError = p; t.standardOutput = p;
            [t launch];
            NSData *d = [p.fileHandleForReading readDataToEndOfFile];
            [t waitUntilExit];
            childOut = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            dispatch_async(dispatch_get_main_queue(), ^{ done = YES; });
        });
        /* the "RDP client" answers 300 ms later, from a different thread */
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 300 * NSEC_PER_MSEC),
                       dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ dispatch_semaphore_signal(prov.gate); });

        /* The daemon's main thread runs the main run loop; so does this test. */
        NSDate *limit = [NSDate dateWithTimeIntervalSinceNow:30];
        while (!done && [limit timeIntervalSinceNow] > 0)
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, false);
        printf("  child reader output: %s\n", childOut.UTF8String ?: "(none)");

        CHECK(done);
        CHECK(prov.calls >= 1);
        CHECK(prov.allOnMain);                                     /* callbacks arrived on the main thread */
        CHECK([childOut containsString:@"<b>from windows</b>|/tmp/macrdp-test-file.txt"]);
        printf("  provider calls=%d\n", prov.calls);
        CHECK(pb.changeCount == cc);                               /* fulfilling does not look like a new copy */
        [pb releaseGlobally];
    }
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
