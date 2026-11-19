#include "protocol/RDPClipboardImage.h"

#include <stdlib.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>

bool rdp_image_has_alpha(const uint8_t *data, size_t len) {
    CFDataRef cf = CFDataCreate(NULL, data, (CFIndex)len);
    if (!cf) return false;
    bool alpha = false;
    CGImageSourceRef src = CGImageSourceCreateWithData(cf, NULL);
    if (src && CGImageSourceGetCount(src) > 0) {
        CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(src, 0, NULL);
        if (props) {
            CFBooleanRef b = (CFBooleanRef)CFDictionaryGetValue(props, kCGImagePropertyHasAlpha);
            alpha = b && CFBooleanGetValue(b);
            CFRelease(props);
        }
    }
    if (src) CFRelease(src);
    CFRelease(cf);
    return alpha;
}

bool rdp_image_decode_bgra(const uint8_t *data, size_t len,
                           uint8_t **bgra, uint32_t *w, uint32_t *h, bool *hasAlpha) {
    if (!data || !len || !bgra || !w || !h) return false;
    bool ok = false;
    CFDataRef cf = CFDataCreate(NULL, data, (CFIndex)len);
    if (!cf) return false;
    CGImageSourceRef src = CGImageSourceCreateWithData(cf, NULL);
    CGImageRef img = NULL;
    if (src && CGImageSourceGetCount(src) > 0) {
        /* The thumbnail path applies the EXIF orientation. Ask for full size. */
        size_t maxDim = 0;
        CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(src, 0, NULL);
        if (props) {
            int pw = 0, ph = 0;
            CFNumberRef nw = (CFNumberRef)CFDictionaryGetValue(props, kCGImagePropertyPixelWidth);
            CFNumberRef nh = (CFNumberRef)CFDictionaryGetValue(props, kCGImagePropertyPixelHeight);
            if (nw) CFNumberGetValue(nw, kCFNumberIntType, &pw);
            if (nh) CFNumberGetValue(nh, kCFNumberIntType, &ph);
            maxDim = (size_t)(pw > ph ? pw : ph);
            CFRelease(props);
        }
        if (maxDim > 0 && maxDim <= 32767) {
            int64_t m = (int64_t)maxDim;
            CFNumberRef nm = CFNumberCreate(NULL, kCFNumberSInt64Type, &m);
            const void *keys[3] = { kCGImageSourceCreateThumbnailFromImageAlways,
                                    kCGImageSourceCreateThumbnailWithTransform,
                                    kCGImageSourceThumbnailMaxPixelSize };
            const void *vals[3] = { kCFBooleanTrue, kCFBooleanTrue, nm };
            CFDictionaryRef opts = CFDictionaryCreate(NULL, keys, vals, 3,
                                                      &kCFTypeDictionaryKeyCallBacks,
                                                      &kCFTypeDictionaryValueCallBacks);
            img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);
            CFRelease(opts);
            CFRelease(nm);
        }
        if (!img) img = CGImageSourceCreateImageAtIndex(src, 0, NULL);
    }
    if (img) {
        size_t iw = CGImageGetWidth(img), ih = CGImageGetHeight(img);
        if (iw > 0 && ih > 0 && iw <= 32767 && ih <= 32767) {
            size_t stride = iw * 4;
            uint8_t *px = (uint8_t *)calloc(ih, stride);
            CGColorSpaceRef cs = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
            if (px && cs) {
                CGContextRef ctx = CGBitmapContextCreate(px, iw, ih, 8, stride, cs,
                    (CGBitmapInfo)kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
                if (ctx) {
                    CGContextSetBlendMode(ctx, kCGBlendModeCopy);
                    CGContextDrawImage(ctx, CGRectMake(0, 0, (CGFloat)iw, (CGFloat)ih), img);
                    CGContextRelease(ctx);
                    bool alpha = false;
                    for (size_t i = 0; i < iw * ih; i++) {
                        uint8_t *p = px + i * 4;
                        uint8_t a = p[3];
                        if (a == 255) continue;
                        alpha = true;
                        if (a == 0) { p[0] = p[1] = p[2] = 0; continue; }
                        for (int c = 0; c < 3; c++) {          /* un-premultiply */
                            unsigned v = ((unsigned)p[c] * 255u + a / 2) / a;
                            p[c] = (uint8_t)(v > 255 ? 255 : v);
                        }
                    }
                    *bgra = px; *w = (uint32_t)iw; *h = (uint32_t)ih;
                    if (hasAlpha) *hasAlpha = alpha;
                    px = NULL;
                    ok = true;
                }
            }
            if (cs) CGColorSpaceRelease(cs);
            free(px);
        }
        CGImageRelease(img);
    }
    if (src) CFRelease(src);
    CFRelease(cf);
    return ok;
}

bool rdp_image_encode(const uint8_t *bgra, uint32_t w, uint32_t h,
                      const char *uti, uint8_t **out, size_t *outLen) {
    if (!bgra || !w || !h || !uti || !out || !outLen) return false;
    bool ok = false;
    size_t bytes = (size_t)w * h * 4;
    CFDataRef pix = CFDataCreate(NULL, bgra, (CFIndex)bytes);
    CGDataProviderRef prov = pix ? CGDataProviderCreateWithCFData(pix) : NULL;
    CGColorSpaceRef cs = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    CGImageRef img = NULL;
    if (prov && cs)
        img = CGImageCreate(w, h, 8, 32, (size_t)w * 4, cs,
                            (CGBitmapInfo)kCGImageAlphaFirst | kCGBitmapByteOrder32Little,
                            prov, NULL, false, kCGRenderingIntentDefault);
    if (img) {
        CFMutableDataRef dst = CFDataCreateMutable(NULL, 0);
        CFStringRef type = CFStringCreateWithCString(NULL, uti, kCFStringEncodingUTF8);
        CGImageDestinationRef dest = (dst && type) ? CGImageDestinationCreateWithData(dst, type, 1, NULL) : NULL;
        if (dest) {
            CGImageDestinationAddImage(dest, img, NULL);
            if (CGImageDestinationFinalize(dest)) {
                size_t n = (size_t)CFDataGetLength(dst);
                uint8_t *buf = (uint8_t *)malloc(n ? n : 1);
                if (buf) { memcpy(buf, CFDataGetBytePtr(dst), n); *out = buf; *outLen = n; ok = true; }
            }
            CFRelease(dest);
        }
        if (type) CFRelease(type);
        if (dst) CFRelease(dst);
        CGImageRelease(img);
    }
    if (cs) CGColorSpaceRelease(cs);
    if (prov) CGDataProviderRelease(prov);
    if (pix) CFRelease(pix);
    return ok;
}
