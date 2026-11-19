#include "audio/ImaAdpcm.h"
#include <stdlib.h>
#include <string.h>

static const int16_t kStep[89] = {
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
    50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230,
    253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963,
    1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327,
    3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442,
    11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794,
    32767 };
static const int8_t kIdxAdj[8] = { -1, -1, -1, -1, 2, 4, 6, 8 };

int ima_block_align(int channels, uint32_t rate) {
    int m = (int)(rate / 11025);
    if (m < 1) m = 1;
    return 256 * channels * m;
}

int ima_samples_per_block(int channels, int blockAlign) {
    return (blockAlign - 4 * channels) * 2 / channels + 1;
}

int ima_encoder_init(ImaEncoder *e, int channels, int blockAlign) {
    memset(e, 0, sizeof *e);
    if (channels < 1 || channels > IMA_MAX_CH) return -1;
    if (blockAlign < 4 * channels + 4 * channels || (blockAlign - 4 * channels) % (4 * channels)) return -1;
    e->channels = channels;
    e->blockAlign = blockAlign;
    e->samplesPerBlock = ima_samples_per_block(channels, blockAlign);
    e->pend = (int16_t *)malloc((size_t)e->samplesPerBlock * (size_t)channels * sizeof(int16_t));
    return e->pend ? 0 : -1;
}

void ima_encoder_free(ImaEncoder *e) {
    free(e->pend);
    memset(e, 0, sizeof *e);
}

/* Encode one sample against the running predictor; returns the 4-bit code. */
static uint8_t enc_sample(int *pred, int *idx, int16_t sample) {
    int step = kStep[*idx];
    int diff = sample - *pred;
    uint8_t code = 0;
    if (diff < 0) { code = 8; diff = -diff; }
    int vpdiff = step >> 3;
    if (diff >= step) { code |= 4; diff -= step; vpdiff += step; }
    step >>= 1;
    if (diff >= step) { code |= 2; diff -= step; vpdiff += step; }
    step >>= 1;
    if (diff >= step) { code |= 1; vpdiff += step; }
    *pred += (code & 8) ? -vpdiff : vpdiff;
    if (*pred > 32767) *pred = 32767;
    if (*pred < -32768) *pred = -32768;
    *idx += kIdxAdj[code & 7];
    if (*idx < 0) *idx = 0;
    if (*idx > 88) *idx = 88;
    return code;
}

static void encode_block(ImaEncoder *e, const int16_t *pcm, uint8_t *out) {
    const int ch = e->channels;
    int pred[IMA_MAX_CH];
    for (int c = 0; c < ch; c++) {
        pred[c] = pcm[c];
        out[4 * c + 0] = (uint8_t)(pcm[c] & 0xFF);
        out[4 * c + 1] = (uint8_t)((pcm[c] >> 8) & 0xFF);
        out[4 * c + 2] = (uint8_t)e->idx[c];
        out[4 * c + 3] = 0;
    }
    uint8_t *o = out + 4 * ch;
    const int groups = (e->blockAlign - 4 * ch) / (4 * ch);
    for (int g = 0; g < groups; g++) {
        for (int c = 0; c < ch; c++) {
            for (int b = 0; b < 4; b++) {
                int n0 = 1 + g * 8 + b * 2;   /* sample 0 is the header sample */
                uint8_t lo = enc_sample(&pred[c], &e->idx[c], pcm[(size_t)n0 * ch + c]);
                uint8_t hi = enc_sample(&pred[c], &e->idx[c], pcm[(size_t)(n0 + 1) * ch + c]);
                *o++ = (uint8_t)(lo | (hi << 4));
            }
        }
    }
}

size_t ima_max_output(const ImaEncoder *e, size_t frames) {
    return ((e->pendFrames + frames) / (size_t)e->samplesPerBlock) * (size_t)e->blockAlign;
}

size_t ima_encode(ImaEncoder *e, const int16_t *pcm, size_t frames,
                  uint8_t *out, size_t outCap) {
    if (outCap < ima_max_output(e, frames)) return 0;
    const size_t ch = (size_t)e->channels, spb = (size_t)e->samplesPerBlock;
    size_t written = 0;
    while (frames > 0) {
        size_t take = spb - e->pendFrames;
        if (take > frames) take = frames;
        memcpy(e->pend + e->pendFrames * ch, pcm, take * ch * sizeof(int16_t));
        e->pendFrames += take; pcm += take * ch; frames -= take;
        if (e->pendFrames == spb) {
            encode_block(e, e->pend, out + written);
            written += (size_t)e->blockAlign;
            e->pendFrames = 0;
        }
    }
    return written;
}
