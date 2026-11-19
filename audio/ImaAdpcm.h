#pragma once
/* Microsoft IMA ADPCM (WAVE_FORMAT_DVI_ADPCM, tag 0x0011) encoder for rdpsnd.
 *
 * FreeRDP 3.10's own ADPCM encoders are compiled out unless WITH_DSP_EXPERIMENTAL
 * (freerdp_dsp_supports_format(ADPCM, encode) is FALSE) and produce no output / garbage, so we encode here and send
 * the finished blocks with rdpsnd SendSamples2 (Wave2 PDU, client version >= 8).
 *
 * Block layout (nBlockAlign bytes): per channel a 4-byte header {int16 first
 * sample, uint8 step index, 0}, then groups of 4 data bytes per channel,
 * channel-interleaved, 8 samples per group, low nibble first. A block carries
 * 1 + (nBlockAlign - 4*ch) * 2 / ch samples per channel. */
#include <stddef.h>
#include <stdint.h>

#define IMA_MAX_CH 2

typedef struct {
    int      channels;
    int      blockAlign;
    int      samplesPerBlock;
    int      idx[IMA_MAX_CH];        /* step index carried between blocks */
    int16_t *pend;                   /* interleaved PCM waiting for a full block */
    size_t   pendFrames;
} ImaEncoder;

/* Standard Windows block size for a rate/channel count (256 * ch * max(1, rate/11025)). */
int ima_block_align(int channels, uint32_t rate);
int ima_samples_per_block(int channels, int blockAlign);
/* 0 on success. */
int  ima_encoder_init(ImaEncoder *e, int channels, int blockAlign);
void ima_encoder_free(ImaEncoder *e);
/* Feed interleaved 16-bit PCM; writes every completed block to out (capacity
 * outCap bytes) and returns the byte count (a multiple of blockAlign). Frames
 * that do not fill a block are kept for the next call. Returns 0 and drops
 * nothing silently if outCap is too small: call again with a bigger buffer. */
size_t ima_encode(ImaEncoder *e, const int16_t *pcm, size_t frames,
                  uint8_t *out, size_t outCap);
/* Upper bound of bytes ima_encode can write for `frames` more input frames. */
size_t ima_max_output(const ImaEncoder *e, size_t frames);
