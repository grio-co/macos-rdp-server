#pragma once
#import <Foundation/Foundation.h>
#import "protocol/RDPClipboard.h"

NS_ASSUME_NONNULL_BEGIN

/*
 * NSPasteboard side of the clipboard bridge (the MS-RDPECLIP protocol itself is
 * protocol/RDPClipboard.c).
 *
 *   Mac -> Windows: polls NSPasteboard.changeCount (macOS has no change
 *     notification), advertises every representation it can serve, and renders
 *     bytes only when the client asks (delayed rendering).
 *   Windows -> Mac: text is fetched eagerly (small, survives a disconnect); HTML,
 *     RTF, images and FILES are put on the pasteboard as promises
 *     (NSPasteboardItemDataProvider) and only transferred when a Mac app pastes.
 *     Provider callbacks arrive on the MAIN thread, so the daemon's main run loop
 *     must be running (see daemon/main.m).
 */
@interface ClipboardSync : NSObject

/* Retains `clip` (balance: -stop). */
- (instancetype)initWithClipboard:(RDPClipboard *)clip;

- (void)start;
/* Detaches from the protocol engine (no more callbacks after it returns) and
 * trims the download cache. Idempotent. */
- (void)stop;

@end

NS_ASSUME_NONNULL_END
