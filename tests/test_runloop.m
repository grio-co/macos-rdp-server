/*
 * Checks the daemon/main.m shutdown pattern in isolation (this is a test program,
 * not the daemon): SIGTERM/SIGINT stay SIG_IGN and are caught by dispatch signal
 * sources on their own queue; the MAIN thread parks in CFRunLoopRun() (so main-queue
 * blocks and NSPasteboard providers are serviced) and returns when the handler calls
 * CFRunLoopStop. Also checks that a main thread stuck inside a callback does not
 * stop the shutdown work from running.
 */
#import <Foundation/Foundation.h>
#include <signal.h>
#include <unistd.h>

int main(void) {
    @autoreleasepool {
        signal(SIGTERM, SIG_IGN);
        signal(SIGINT,  SIG_IGN);
        __block int shutdownRan = 0, mainQueueRan = 0, onMainThread = 0;
        dispatch_queue_t q = dispatch_queue_create("signals", DISPATCH_QUEUE_SERIAL);
        dispatch_source_t term = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, q);
        dispatch_source_set_event_handler(term, ^{
            shutdownRan = 1;
            CFRunLoopStop(CFRunLoopGetMain());
        });
        dispatch_resume(term);

        /* a main-queue block must run while we are parked in the run loop */
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
            mainQueueRan = 1;
            onMainThread = [NSThread isMainThread];
            /* simulate a paste blocking the main thread; the signal arrives meanwhile */
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC),
                           dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ kill(getpid(), SIGTERM); });
            usleep(400000);
        });

        CFRunLoopTimerRef keep = CFRunLoopTimerCreateWithHandler(kCFAllocatorDefault,
            CFAbsoluteTimeGetCurrent() + 3600, 3600, 0, 0, ^(CFRunLoopTimerRef t) { (void)t; });
        CFRunLoopAddTimer(CFRunLoopGetMain(), keep, kCFRunLoopCommonModes);
        CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
        CFRunLoopRun();
        double dt = CFAbsoluteTimeGetCurrent() - t0;

        int ok = shutdownRan && mainQueueRan && onMainThread && dt > 0.5 && dt < 5.0;
        printf("  mainQueueRan=%d onMainThread=%d shutdownRan=%d runloop returned after %.2fs\n",
               mainQueueRan, onMainThread, shutdownRan, dt);
        printf("%s\n", ok ? "1 passed, 0 failed" : "0 passed, 1 failed");
        return ok ? 0 : 1;
    }
}
