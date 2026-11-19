#import "input/ClipboardSync.h"
#import <AppKit/AppKit.h>
#include <stdatomic.h>
#include "protocol/RDPClipboardCodec.h"
#include "protocol/RDPClipboardImage.h"
#define RDP_LOG_COMPONENT "clipboard"
#include "logging/RDPLog.h"

/*
 * macOS provides NO pasteboard-change notification (NSPasteboard has no KVO and
 * no NSNotification for content changes). The only reliable way to detect a copy
 * is to poll NSPasteboard.changeCount. We poll a few times a second; when idle
 * this is just an integer comparison.
 */

/* Private marker type present on every item WE put on the pasteboard on behalf of
 * the client. The poller skips such changes, so data that came from Windows is
 * never advertised back (no clipboard ping-pong). */
static NSPasteboardType const kOriginMarker = @"com.macosrdp.clipboard-origin";

static NSArray<NSPasteboardType> *ImageTypes(void) {
    static NSArray *t;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        t = @[NSPasteboardTypePNG, NSPasteboardTypeTIFF, @"public.jpeg", @"public.heic", @"public.heif"];
    });
    return t;
}

static NSString *WinToMacNewlines(NSString *s) {
    return [s stringByReplacingOccurrencesOfString:@"\r\n" withString:@"\n"];
}
static NSString *MacToWinNewlines(NSString *s) {
    s = [s stringByReplacingOccurrencesOfString:@"\r\n" withString:@"\n"];
    return [s stringByReplacingOccurrencesOfString:@"\n" withString:@"\r\n"];
}

static uint8_t *CopyBytes(NSData *d, size_t *len) {
    if (!d) return NULL;
    uint8_t *p = (uint8_t *)malloc(d.length ? d.length : 1);
    if (!p) return NULL;
    if (d.length) memcpy(p, d.bytes, d.length);
    *len = d.length;
    return p;
}

/* ── per-item data provider ───────────────────────────────────────────────── */

@class ClipboardSync;
@interface ClipProvider : NSObject <NSPasteboardItemDataProvider>
@property (nonatomic, strong) ClipboardSync *owner;
@property (nonatomic, assign) uint64_t gen;
@property (nonatomic, assign) int fileOrdinal;   /* -1: not a file item */
- (void)provideForItem:(NSPasteboardItem *)item type:(NSPasteboardType)type;
@end

@interface ClipboardSync ()
@property (nonatomic, strong) dispatch_source_t pollTimer;
- (uint8_t *)renderKind:(uint32_t)kind token:(uint64_t)token length:(size_t *)len;
- (void)clientClipboardChanged:(uint64_t)gen formats:(NSArray<NSDictionary *> *)fmts
                 topLevelNames:(NSArray<NSString *> *)tops;
- (void)fulfillItem:(NSPasteboardItem *)item type:(NSPasteboardType)type gen:(uint64_t)gen fileOrdinal:(int)ord;
@end

@implementation ClipboardSync {
    RDPClipboard *_clip;                 /* retained; guarded by @synchronized(self) */
    NSInteger     _lastChangeCount;      /* poll queue only */
    _Atomic uint64_t _latestGen;
    dispatch_queue_t _clientQueue;       /* serial: eager Windows->Mac fetches */
    NSMutableArray<ClipProvider *> *_providers;   /* @synchronized(self) */
    /* Windows->Mac state for the current client generation (@synchronized(self)) */
    NSArray<NSDictionary *> *_fmts;      /* {id, name} */
    uint64_t      _fmtsGen;
    NSString     *_downloadDir;          /* per-generation cache folder, lazily made */
    uint64_t      _downloadGen;
    uint64_t      _imageGen;             /* decoded-image cache */
    NSData       *_imageBGRA;
    uint32_t      _imageW, _imageH;
    NSData       *_imagePNG;
}

- (instancetype)initWithClipboard:(RDPClipboard *)clip {
    if ((self = [super init])) {
        _clip = rdp_clip_retain(clip);
        _clientQueue = dispatch_queue_create("com.macosrdp.clipboard.client", DISPATCH_QUEUE_SERIAL);
        _providers = [NSMutableArray array];
    }
    return self;
}

- (void)dealloc {
    if (_clip) { rdp_clip_release(_clip); _clip = NULL; }
}

- (RDPClipboard *)retainedClip {
    @synchronized (self) { return rdp_clip_retain(_clip); }
}

/* ── lifecycle ────────────────────────────────────────────────────────────── */

static uint8_t *host_render(void *user, uint32_t kind, uint64_t token, size_t *len) {
    return [(__bridge ClipboardSync *)user renderKind:kind token:token length:len];
}

static void host_client_clipboard(void *user, uint64_t gen, const RDPClipFormat *fmts, uint32_t n,
                                  const RDPFileDesc *files, uint32_t nf) {
    NSMutableArray *f = [NSMutableArray arrayWithCapacity:n];
    for (uint32_t i = 0; i < n; i++)
        [f addObject:@{ @"id": @(fmts[i].id), @"name": [NSString stringWithUTF8String:fmts[i].name] ?: @"" }];
    NSMutableArray<NSString *> *tops = [NSMutableArray array];
    for (uint32_t i = 0; i < nf; i++) {
        if (!files[i].name || !files[i].name[0] || strchr(files[i].name, '\\')) continue;
        [tops addObject:[NSString stringWithUTF8String:files[i].name] ?: @"file"];
    }
    [(__bridge ClipboardSync *)user clientClipboardChanged:gen formats:f topLevelNames:tops];
}

- (void)start {
    _lastChangeCount = NSPasteboard.generalPasteboard.changeCount;
    [self trimDownloadCacheKeeping:1];

    RDPClipHost host = { .user = (__bridge void *)self,
                         .render = host_render,
                         .client_clipboard = host_client_clipboard };
    RDPClipboard *clip = [self retainedClip];
    if (clip) { rdp_clip_set_host(clip, &host); rdp_clip_release(clip); }

    _pollTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                    dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_timer(_pollTimer, dispatch_time(DISPATCH_TIME_NOW, 0),
                              (uint64_t)(NSEC_PER_SEC / 4), NSEC_PER_SEC / 8); /* ~4 Hz */
    __weak typeof(self) weak = self;
    dispatch_source_set_event_handler(_pollTimer, ^{ [weak pollPasteboard]; });
    dispatch_resume(_pollTimer);
    rdp_verbose("clipboard sync started (polling changeCount ~4Hz)");
}

- (void)stop {
    if (_pollTimer) { dispatch_source_cancel(_pollTimer); _pollTimer = nil; }
    RDPClipboard *clip;
    @synchronized (self) { clip = _clip; _clip = NULL; [_providers removeAllObjects]; }
    if (clip) {
        rdp_clip_set_host(clip, NULL);       /* waits out in-flight host callbacks */
        rdp_clip_release(clip);
    }
    [self trimDownloadCacheKeeping:1];
    rdp_verbose("clipboard sync stopped");
}

/* ── Mac -> Windows ───────────────────────────────────────────────────────── */

- (void)pollPasteboard {
    NSPasteboard *pb = NSPasteboard.generalPasteboard;
    NSInteger cc = pb.changeCount;
    if (cc == _lastChangeCount) return;
    _lastChangeCount = cc;

    NSArray<NSPasteboardType> *types = pb.types;
    if ([types containsObject:kOriginMarker]) return;      /* our own write for the client */

    RDPClipboard *clip = [self retainedClip];
    if (!clip) return;

    uint32_t kinds = 0;
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    NSArray *urls = [pb readObjectsForClasses:@[NSURL.class]
                                      options:@{ NSPasteboardURLReadingFileURLsOnlyKey: @YES }];
    for (NSURL *u in urls)
        if (u.isFileURL && u.path.length) [paths addObject:u.path];

    if (paths.count) {
        kinds = RDP_CLIP_KIND_FILES;               /* files win; Finder's text is just the name */
    } else {
        if ([types containsObject:NSPasteboardTypeString]) kinds |= RDP_CLIP_KIND_TEXT;
        if ([types containsObject:NSPasteboardTypeHTML])   kinds |= RDP_CLIP_KIND_HTML;
        if ([types containsObject:NSPasteboardTypeRTF])    kinds |= RDP_CLIP_KIND_RTF;
        for (NSPasteboardType t in ImageTypes()) {
            if (![types containsObject:t]) continue;
            kinds |= RDP_CLIP_KIND_PNG | RDP_CLIP_KIND_DIB;
            NSData *d = [pb dataForType:t];
            if (d && rdp_image_has_alpha(d.bytes, d.length)) kinds |= RDP_CLIP_KIND_DIBV5;
            break;
        }
    }
    if (kinds) {
        const char **cpaths = (const char **)calloc(paths.count ? paths.count : 1, sizeof(char *));
        for (NSUInteger i = 0; i < paths.count; i++) cpaths[i] = paths[i].fileSystemRepresentation;
        rdp_clip_advertise(clip, kinds, (uint64_t)cc, cpaths, paths.count);
        free(cpaths);
    }
    rdp_clip_release(clip);
}

/* Which Mac image representation is on the pasteboard, decoded to BGRA. */
- (BOOL)macImageBGRA:(NSPasteboard *)pb out:(uint8_t **)bgra w:(uint32_t *)w h:(uint32_t *)h {
    for (NSPasteboardType t in ImageTypes()) {
        NSData *d = [pb dataForType:t];
        if (d && rdp_image_decode_bgra(d.bytes, d.length, bgra, w, h, NULL)) return YES;
    }
    return NO;
}

/* Worker thread (RDPClipHost.render): bytes in Windows wire format. */
- (uint8_t *)renderKind:(uint32_t)kind token:(uint64_t)token length:(size_t *)len {
    NSPasteboard *pb = NSPasteboard.generalPasteboard;
    if ((uint64_t)pb.changeCount != token) {
        rdp_verbose("clipboard: pasteboard changed since advertise — refusing stale render");
        return NULL;
    }
    switch (kind) {
    case RDP_CLIP_KIND_TEXT:
    case RDP_CLIP_KIND_ANSI: {
        NSString *s = [pb stringForType:NSPasteboardTypeString];
        if (!s) return NULL;
        s = MacToWinNewlines(s);
        /* MS-RDPECLIP: text data is NUL-terminated; large blocks go out in full. */
        NSMutableData *out;
        if (kind == RDP_CLIP_KIND_TEXT) {
            out = [[s dataUsingEncoding:NSUTF16LittleEndianStringEncoding] mutableCopy];
            const uint16_t nul = 0;
            [out appendBytes:&nul length:sizeof(nul)];
        } else {
            out = [[s dataUsingEncoding:NSWindowsCP1252StringEncoding allowLossyConversion:YES] mutableCopy];
            const uint8_t nul = 0;
            [out appendBytes:&nul length:1];
        }
        return out ? CopyBytes(out, len) : NULL;
    }
    case RDP_CLIP_KIND_HTML: {
        NSData *d = [pb dataForType:NSPasteboardTypeHTML];
        if (!d.length) return NULL;
        NSData *utf8 = d;
        const uint8_t *b = d.bytes;
        BOOL bom16 = d.length >= 2 && ((b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF));
        NSString *s = nil;
        if (bom16) s = [[NSString alloc] initWithData:d encoding:NSUTF16StringEncoding];
        else if (![[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding])
            s = [[NSString alloc] initWithData:d encoding:NSWindowsCP1252StringEncoding];
        if (s) utf8 = [s dataUsingEncoding:NSUTF8StringEncoding];
        if (!utf8) return NULL;
        uint8_t *out = NULL; size_t n = 0;
        if (!rdp_cf_html_build(utf8.bytes, utf8.length, &out, &n)) return NULL;
        *len = n;
        return out;
    }
    case RDP_CLIP_KIND_RTF: {
        NSData *d = [pb dataForType:NSPasteboardTypeRTF];
        if (!d.length) return NULL;
        NSMutableData *out = [d mutableCopy];
        const uint8_t nul = 0;
        [out appendBytes:&nul length:1];
        return CopyBytes(out, len);
    }
    case RDP_CLIP_KIND_PNG: {
        NSData *png = [pb dataForType:NSPasteboardTypePNG];
        if (png.length) return CopyBytes(png, len);
        uint8_t *bgra = NULL; uint32_t w = 0, h = 0;
        if (![self macImageBGRA:pb out:&bgra w:&w h:&h]) return NULL;
        uint8_t *out = NULL; size_t n = 0;
        bool ok = rdp_image_encode(bgra, w, h, "public.png", &out, &n);
        free(bgra);
        if (!ok) return NULL;
        *len = n;
        return out;
    }
    case RDP_CLIP_KIND_DIB:
    case RDP_CLIP_KIND_DIBV5: {
        uint8_t *bgra = NULL; uint32_t w = 0, h = 0;
        if (![self macImageBGRA:pb out:&bgra w:&w h:&h]) return NULL;
        uint8_t *out = NULL; size_t n = 0;
        bool ok = rdp_dib_encode(bgra, w, h, kind == RDP_CLIP_KIND_DIBV5, &out, &n);
        free(bgra);
        if (!ok) return NULL;
        *len = n;
        return out;
    }
    default:
        return NULL;
    }
}

/* ── Windows -> Mac ───────────────────────────────────────────────────────── */

- (NSArray<NSDictionary *> *)currentFormats {
    @synchronized (self) { return _fmts; }
}
- (uint32_t)idForName:(NSString *)name {
    for (NSDictionary *f in [self currentFormats])
        if ([f[@"name"] isEqualToString:name]) return [f[@"id"] unsignedIntValue];
    return 0;
}
- (BOOL)hasId:(uint32_t)fid {
    for (NSDictionary *f in [self currentFormats])
        if ([f[@"id"] unsignedIntValue] == fid && [f[@"name"] length] == 0) return YES;
    return NO;
}

/* Run-loop thread, must not block: hand off to the client queue. */
- (void)clientClipboardChanged:(uint64_t)gen formats:(NSArray<NSDictionary *> *)fmts
                 topLevelNames:(NSArray<NSString *> *)tops {
    atomic_store(&_latestGen, gen);
    @synchronized (self) { _fmts = fmts; _fmtsGen = gen; }
    dispatch_async(_clientQueue, ^{ [self applyClientClipboard:gen formats:fmts tops:tops]; });
}

- (void)applyClientClipboard:(uint64_t)gen formats:(NSArray<NSDictionary *> *)fmts tops:(NSArray<NSString *> *)tops {
    if (gen != atomic_load(&_latestGen)) return;
    RDPClipboard *clip = [self retainedClip];
    if (!clip) return;

    uint32_t unicodeId = 0, ansiId = 0, htmlId = 0, rtfId = 0, pngId = 0, dibId = 0, dib5Id = 0;
    for (NSDictionary *f in fmts) {
        uint32_t i = [f[@"id"] unsignedIntValue];
        NSString *n = f[@"name"];
        if (n.length == 0) {
            if (i == RDP_CF_UNICODETEXT) unicodeId = i;
            else if (i == RDP_CF_TEXT || i == RDP_CF_OEMTEXT) { if (!ansiId || i == RDP_CF_TEXT) ansiId = i; }
            else if (i == RDP_CF_DIB) dibId = i;
            else if (i == RDP_CF_DIBV5) dib5Id = i;
        } else if ([n isEqualToString:@RDP_FMT_NAME_HTML]) htmlId = i;
        else if ([n isEqualToString:@RDP_FMT_NAME_RTF]) rtfId = i;
        else if ([n isEqualToString:@RDP_FMT_NAME_PNG] || [n isEqualToString:@"image/png"]) pngId = i;
    }
    BOOL files = tops.count > 0;

    /* Text is small and valuable after a disconnect: fetch it now. Everything else
     * stays a promise until a Mac app actually pastes. */
    NSString *text = nil;
    if (!files && (unicodeId || ansiId)) {
        size_t n = 0;
        uint8_t *d = rdp_clip_fetch_format(clip, gen, unicodeId ? unicodeId : ansiId, &n);
        if (d) {
            if (unicodeId) {
                size_t blen = n;
                if (blen >= 2 && d[blen - 1] == 0 && d[blen - 2] == 0) blen -= 2;   /* trailing U+0000 */
                text = [[NSString alloc] initWithBytes:d length:blen & ~(size_t)1 encoding:NSUTF16LittleEndianStringEncoding];
            } else {
                size_t blen = n;
                while (blen > 0 && d[blen - 1] == 0) blen--;
                text = [[NSString alloc] initWithBytes:d length:blen encoding:NSWindowsCP1252StringEncoding];
            }
            free(d);
            if (text) text = WinToMacNewlines(text);
        }
    }
    rdp_clip_release(clip);
    if (gen != atomic_load(&_latestGen)) return;

    dispatch_async(dispatch_get_main_queue(), ^{
        if (gen != atomic_load(&self->_latestGen)) return;
        NSMutableArray<NSPasteboardItem *> *items = [NSMutableArray array];
        NSMutableArray<ClipProvider *> *providers = [NSMutableArray array];
        if (files) {
            for (NSUInteger i = 0; i < tops.count; i++) {
                NSPasteboardItem *item = [[NSPasteboardItem alloc] init];
                ClipProvider *p = [[ClipProvider alloc] init];
                p.owner = self; p.gen = gen; p.fileOrdinal = (int)i;
                [item setString:@"1" forType:kOriginMarker];
                [item setDataProvider:p forTypes:@[NSPasteboardTypeFileURL]];
                [items addObject:item]; [providers addObject:p];
            }
        } else {
            NSPasteboardItem *item = [[NSPasteboardItem alloc] init];
            ClipProvider *p = [[ClipProvider alloc] init];
            p.owner = self; p.gen = gen; p.fileOrdinal = -1;
            NSMutableArray<NSPasteboardType> *lazy = [NSMutableArray array];
            if (htmlId) [lazy addObject:NSPasteboardTypeHTML];
            if (rtfId)  [lazy addObject:NSPasteboardTypeRTF];
            if (pngId || dib5Id || dibId) { [lazy addObject:NSPasteboardTypePNG]; [lazy addObject:NSPasteboardTypeTIFF]; }
            if (!text && !lazy.count) return;           /* nothing we can represent */
            [item setString:@"1" forType:kOriginMarker];
            if (text) [item setString:text forType:NSPasteboardTypeString];
            if (lazy.count) [item setDataProvider:p forTypes:lazy];
            [items addObject:item]; [providers addObject:p];
        }
        NSPasteboard *pb = NSPasteboard.generalPasteboard;
        [pb clearContents];
        [pb writeObjects:items];
        @synchronized (self) { self->_providers = providers; }
        [self trimDownloadCacheKeeping:1];
        rdp_verbose("clipboard: client copy gen=%llu -> pasteboard (%s%s)", (unsigned long long)gen,
                    files ? "files" : (text ? "text+" : ""), files ? "" : "promises");
    });
}

/* Provider callback body — MAIN thread, blocks until the client answers. */
- (void)fulfillItem:(NSPasteboardItem *)item type:(NSPasteboardType)type gen:(uint64_t)gen fileOrdinal:(int)ord {
    RDPClipboard *clip = [self retainedClip];
    if (!clip) { rdp_verbose("clipboard: promise for %s after teardown — no data", type.UTF8String); return; }
    @try {
        if (ord >= 0) {
            NSString *root = [self downloadRootForGen:gen];
            char *path = rdp_clip_fetch_file(clip, gen, (uint32_t)ord, root.fileSystemRepresentation);
            if (path) {
                NSURL *u = [NSURL fileURLWithPath:[NSString stringWithUTF8String:path]];
                [item setString:u.absoluteString forType:NSPasteboardTypeFileURL];
                free(path);
            }
            return;
        }
        if ([type isEqualToString:NSPasteboardTypeHTML]) {
            uint32_t id_ = [self idForName:@RDP_FMT_NAME_HTML];
            size_t n = 0; uint8_t *d = id_ ? rdp_clip_fetch_format(clip, gen, id_, &n) : NULL;
            if (!d) return;
            const uint8_t *html, *frag; size_t hl, fl;
            if (rdp_cf_html_parse(d, n, &html, &hl, &frag, &fl)) {
                NSMutableData *out = [NSMutableData data];
                /* Mac HTML importers assume nothing about the charset of a bare
                 * pasteboard string; CF_HTML is UTF-8, so say so. */
                NSData *head = [NSData dataWithBytes:html length:MIN(hl, (size_t)2048)];
                NSString *hs = [[NSString alloc] initWithData:head encoding:NSISOLatin1StringEncoding];
                if ([hs rangeOfString:@"charset" options:NSCaseInsensitiveSearch].location == NSNotFound)
                    [out appendData:[@"<meta charset=\"utf-8\">" dataUsingEncoding:NSUTF8StringEncoding]];
                [out appendBytes:html length:hl];
                [item setData:out forType:NSPasteboardTypeHTML];
            }
            free(d);
        } else if ([type isEqualToString:NSPasteboardTypeRTF]) {
            uint32_t id_ = [self idForName:@RDP_FMT_NAME_RTF];
            size_t n = 0; uint8_t *d = id_ ? rdp_clip_fetch_format(clip, gen, id_, &n) : NULL;
            if (!d) return;
            while (n > 0 && d[n - 1] == 0) n--;
            if (n) [item setData:[NSData dataWithBytes:d length:n] forType:NSPasteboardTypeRTF];
            free(d);
        } else if ([type isEqualToString:NSPasteboardTypePNG] || [type isEqualToString:NSPasteboardTypeTIFF]) {
            if (![self loadClientImage:clip gen:gen]) return;
            NSData *out = nil;
            @synchronized (self) {
                if ([type isEqualToString:NSPasteboardTypePNG]) out = _imagePNG;
                else {
                    uint8_t *t = NULL; size_t tn = 0;
                    if (rdp_image_encode(_imageBGRA.bytes, _imageW, _imageH, "public.tiff", &t, &tn))
                        out = [NSData dataWithBytesNoCopy:t length:tn freeWhenDone:YES];
                }
            }
            if (out) [item setData:out forType:type];
        }
    } @finally {
        rdp_clip_release(clip);
    }
}

/* Fetch + decode the client's best image representation (cached per generation). */
- (BOOL)loadClientImage:(RDPClipboard *)clip gen:(uint64_t)gen {
    @synchronized (self) { if (_imageGen == gen && _imageBGRA) return YES; }
    uint32_t pngId = [self idForName:@RDP_FMT_NAME_PNG];
    if (!pngId) pngId = [self idForName:@"image/png"];
    uint32_t cands[3] = { pngId, RDP_CF_DIBV5, RDP_CF_DIB };
    for (int k = 0; k < 3; k++) {
        uint32_t fid = cands[k];
        if (!fid || (k > 0 && ![self hasId:fid])) continue;
        size_t n = 0;
        uint8_t *d = rdp_clip_fetch_format(clip, gen, fid, &n);
        if (!d) continue;
        uint8_t *bgra = NULL; uint32_t w = 0, h = 0; BOOL ok = NO;
        NSData *png = nil;
        if (k == 0) {
            ok = rdp_image_decode_bgra(d, n, &bgra, &w, &h, NULL);
            if (ok) png = [NSData dataWithBytes:d length:n];
        } else {
            RDPBitmap bm;
            if (rdp_dib_decode(d, n, &bm)) { bgra = bm.bgra; w = bm.width; h = bm.height; ok = YES; }
        }
        free(d);
        if (!ok) continue;
        if (!png) {
            uint8_t *p = NULL; size_t pn = 0;
            if (rdp_image_encode(bgra, w, h, "public.png", &p, &pn))
                png = [NSData dataWithBytesNoCopy:p length:pn freeWhenDone:YES];
        }
        NSData *px = [NSData dataWithBytesNoCopy:bgra length:(size_t)w * h * 4 freeWhenDone:YES];
        if (!png) continue;
        @synchronized (self) { _imageGen = gen; _imageBGRA = px; _imageW = w; _imageH = h; _imagePNG = png; }
        return YES;
    }
    return NO;
}

/* ── download cache ───────────────────────────────────────────────────────── */

- (NSString *)cacheRoot {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches/com.macosrdp.daemon/clipboard"];
}

- (NSString *)downloadRootForGen:(uint64_t)gen {
    @synchronized (self) {
        if (_downloadDir && _downloadGen == gen) return _downloadDir;
        NSString *dir = [[self cacheRoot] stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"%llu-%@", (unsigned long long)gen, NSUUID.UUID.UUIDString]];
        [NSFileManager.defaultManager createDirectoryAtPath:dir withIntermediateDirectories:YES
                                                 attributes:@{ NSFilePosixPermissions: @0755 } error:NULL];
        _downloadDir = dir; _downloadGen = gen;
        return dir;
    }
}

/* Remove all but the `keep` most recently modified paste folders. */
- (void)trimDownloadCacheKeeping:(NSUInteger)keep {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *root = [self cacheRoot];
    NSArray<NSString *> *names = [fm contentsOfDirectoryAtPath:root error:NULL];
    if (names.count <= keep) return;
    NSMutableArray<NSDictionary *> *dirs = [NSMutableArray array];
    for (NSString *n in names) {
        NSString *p = [root stringByAppendingPathComponent:n];
        NSDate *m = [fm attributesOfItemAtPath:p error:NULL].fileModificationDate ?: NSDate.distantPast;
        [dirs addObject:@{ @"p": p, @"m": m }];
    }
    [dirs sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [b[@"m"] compare:a[@"m"]];       /* newest first */
    }];
    NSString *current;
    @synchronized (self) { current = _downloadDir; }
    for (NSUInteger i = keep; i < dirs.count; i++) {
        NSString *p = dirs[i][@"p"];
        if (current && [p isEqualToString:current]) continue;    /* never pull the rug from a live paste */
        [fm removeItemAtPath:p error:NULL];
    }
}

@end

@implementation ClipProvider
- (void)pasteboard:(NSPasteboard *)pasteboard item:(NSPasteboardItem *)item provideDataForType:(NSPasteboardType)type {
    [self.owner fulfillItem:item type:type gen:self.gen fileOrdinal:self.fileOrdinal];
}
- (void)pasteboardFinishedWithDataProvider:(NSPasteboard *)pasteboard {
    /* The pasteboard moved on; our providers are released when the owner next
     * replaces them (or at -stop). */
}
- (void)provideForItem:(NSPasteboardItem *)item type:(NSPasteboardType)type {
    [self.owner fulfillItem:item type:type gen:self.gen fileOrdinal:self.fileOrdinal];
}
@end
