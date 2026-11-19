#pragma once
/* ImageIO bridge for clipboard images: any ImageIO-readable format <-> BGRA. */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Decode PNG/TIFF/JPEG/HEIC/GIF/... (EXIF orientation applied) to top-down,
 * straight-alpha BGRA. *bgra is malloc'd. */
bool rdp_image_decode_bgra(const uint8_t *data, size_t len,
                           uint8_t **bgra, uint32_t *w, uint32_t *h, bool *hasAlpha);

/* Encode straight-alpha BGRA as "public.png" / "public.tiff" / ... *out is
 * malloc'd. */
bool rdp_image_encode(const uint8_t *bgra, uint32_t w, uint32_t h,
                      const char *uti, uint8_t **out, size_t *outLen);

/* Metadata-only probe (no pixel decode): does the encoded image carry alpha? */
bool rdp_image_has_alpha(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif
