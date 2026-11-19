#pragma once
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/*
 * Silent self-updater for the RDP daemon.
 *
 * On +start it does an immediate check, then re-checks every
 * RDP_UPDATE_INTERVAL_MIN minutes on a dispatch_source timer running on a
 * private background serial queue (the daemon's main thread is parked in
 * kevent(), so there is NO main run loop — see daemon/main.m). Every network,
 * codesign and filesystem operation is wrapped so a failure only logs and
 * retries on the next interval; the running daemon is never bricked.
 *
 * Configuration (all environment variables):
 *   RDP_UPDATE_ENABLED       "1" (default) enables; "0" disables entirely.
 *   RDP_UPDATE_INTERVAL_MIN  Check interval in minutes (default 5).
 *   RDP_UPDATE_REPO          GitHub "owner/repo" (default grioghar/macos-rdp-server).
 *   RDP_UPDATE_TOKEN         Optional Bearer token for a private repo.
 *
 * Updates are never re-signed. A downloaded binary is installed only if it is
 * strictly newer than the running version (release tags such as v0.1.7,
 * compared numerically; a running build not stamped with a tag never updates)
 * and passes SecStaticCodeCheckValidity against: anchor apple generic, leaf OU
 * FQKL8883DP, identifier com.macosrdp.daemon, hardened runtime. Release
 * binaries must therefore be built with scripts/build-local.sh.
 */
@interface AutoUpdate : NSObject

/* Start the singleton updater. Safe to call once at daemon launch. No-op when
 * RDP_UPDATE_ENABLED=0. */
+ (void)start;

/* Stop the timer (used on shutdown; optional). */
+ (void)stop;

@end

NS_ASSUME_NONNULL_END
