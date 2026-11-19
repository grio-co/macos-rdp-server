#pragma once
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#include "protocol/RDPPeer.h"

NS_ASSUME_NONNULL_BEGIN

/*
 * DisplayArrangement: where the session's virtual displays sit in the Mac's
 * global display space, and putting the physical displays back afterwards.
 *
 *   - The client's primary monitor becomes the Mac's main display (global
 *     origin), so the menu bar, Dock and new windows land on what the remote
 *     user sees.
 *   - The other monitors are placed as they are on the client (left/right/
 *     above/below), converted to points per monitor, so moving the pointer or a
 *     window across a monitor edge behaves as it does on the client.
 *   - Physical displays move aside (to the right of the virtual desktop, their
 *     own arrangement kept), or with RDP_PHYSICAL_DISPLAYS=mirror they mirror
 *     the primary virtual display so no window can open where the remote user
 *     can't see it.
 *
 * Changes use kCGConfigureForSession; -restore reapplies the origins captured at
 * init, once the virtual displays are gone.
 */
@interface DisplayArrangement : NSObject

/* Snapshots the current origin of every active display. */
- (instancetype)init;

/* displayIDs[i] serves layout->monitors[i]. */
- (void)arrangeDisplays:(NSArray<NSNumber *> *)displayIDs
                 layout:(const RDPMonitorLayout *)layout;

/* Call after the virtual displays were destroyed. Waits (bounded) for them to
 * go offline, then restores the physical displays' original origins. */
- (void)restoreAfterRemoving:(NSArray<NSNumber *> *)virtualIDs;

@end

NS_ASSUME_NONNULL_END
