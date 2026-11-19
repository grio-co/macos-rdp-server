/* audio/ImaAdpcm.c: block layout, round trip through an independent decoder. */
#include "audio/ImaAdpcm.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

static const int step_tab[89] = {7,8,9,10,11,12,13,14,16,17,19,21,23,25,28,31,34,37,41,45,50,55,60,66,73,80,88,97,107,118,130,143,157,173,190,209,230,253,279,307,337,371,408,449,494,544,598,658,724,796,876,963,1060,1166,1282,1411,1552,1707,1878,2066,2272,2499,2749,3024,3327,3660,4026,4428,4871,5358,5894,6484,7132,7845,8630,9493,10442,11487,12635,13899,15289,16818,18500,20350,22385,24623,27086,29794,32767};
static const int adj[16] = {-1,-1,-1,-1,2,4,6,8,-1,-1,-1,-1,2,4,6,8};

static int dec_nibble(int *p, int *ix, int n) {
    int step = step_tab[*ix];
    int d = step >> 3;
    if (n & 4) d += step;
    if (n & 2) d += step >> 1;
    if (n & 1) d += step >> 2;
    *p += (n & 8) ? -d : d;
    if (*p > 32767) *p = 32767;
    if (*p < -32768) *p = -32768;
    *ix += adj[n];
    if (*ix < 0) *ix = 0;
    if (*ix > 88) *ix = 88;
    return *p;
}

/* Reference decoder of one block. out has samplesPerBlock*ch entries. */
static void dec_block(const uint8_t *b, int ch, int blockAlign, int16_t *out) {
    int p[2], ix[2];
    for (int c = 0; c < ch; c++) {
        p[c] = (int16_t)(b[4*c] | (b[4*c+1] << 8)); ix[c] = b[4*c+2];
        out[c] = (int16_t)p[c];
    }
    const uint8_t *q = b + 4 * ch;
    int groups = (blockAlign - 4 * ch) / (4 * ch);
    for (int g = 0; g < groups; g++)
        for (int c = 0; c < ch; c++)
            for (int k = 0; k < 4; k++) {
                uint8_t v = *q++;
                int n = 1 + g * 8 + k * 2;
                out[(size_t)n * ch + c] = (int16_t)dec_nibble(&p[c], &ix[c], v & 15);
                out[(size_t)(n + 1) * ch + c] = (int16_t)dec_nibble(&p[c], &ix[c], v >> 4);
            }
}

static void roundtrip(int ch, uint32_t rate, double minSnr) {
    int ba = ima_block_align(ch, rate), spb = ima_samples_per_block(ch, ba);
    ImaEncoder e; CHECK(ima_encoder_init(&e, ch, ba) == 0);
    size_t total = (size_t)spb * 20 + 77;      /* not a block multiple */
    int16_t *pcm = malloc(total * ch * 2), *dec = malloc((size_t)spb * ch * 2);
    for (size_t i = 0; i < total; i++)
        for (int c = 0; c < ch; c++)
            pcm[i*ch+c] = (int16_t)(9000*sin(2*M_PI*440*i/rate) + 4000*sin(2*M_PI*3100.0*i/rate + c));
    uint8_t *out = malloc(ima_max_output(&e, total) + 1);
    /* feed in odd-sized chunks, as the audio tap does */
    size_t pos = 0, bytes = 0;
    while (pos < total) {
        size_t n = 441 + (pos % 13); if (pos + n > total) n = total - pos;
        bytes += ima_encode(&e, pcm + pos * ch, n, out + bytes, ima_max_output(&e, n));
        pos += n;
    }
    CHECK(bytes == (size_t)ba * 20);
    CHECK(e.pendFrames == 77);
    double sig = 0, err = 0;
    for (int blk = 0; blk < 20; blk++) {
        dec_block(out + (size_t)blk * ba, ch, ba, dec);
        for (int i = 0; i < spb; i++)
            for (int c = 0; c < ch; c++) {
                double a = pcm[((size_t)blk * spb + i) * ch + c], d = dec[(size_t)i * ch + c];
                sig += a * a; err += (a - d) * (a - d);
            }
    }
    double snr = 10 * log10(sig / (err + 1));
    printf("  %uch %uHz blockAlign %d: %d samples/block, SNR %.1f dB, %.2f:1\n", ch, rate, ba, spb, snr,
           2.0 * spb * ch / ba);
    CHECK(snr > minSnr);
    ima_encoder_free(&e); free(pcm); free(dec); free(out);
}

int main(void) {
    CHECK(ima_block_align(2, 44100) == 2048 && ima_samples_per_block(2, 2048) == 2041);
    CHECK(ima_block_align(2, 22050) == 1024 && ima_samples_per_block(2, 1024) == 1017);
    CHECK(ima_block_align(1, 44100) == 1024 && ima_samples_per_block(1, 1024) == 2041);
    roundtrip(2, 44100, 25);
    roundtrip(2, 48000, 25);
    roundtrip(2, 22050, 25);
    roundtrip(1, 44100, 25);
    /* silence and full-scale square must not crash or overflow */
    ImaEncoder e; ima_encoder_init(&e, 2, 2048);
    int16_t *sq = malloc(2041 * 2 * 2);
    for (int i = 0; i < 2041 * 2; i++) sq[i] = (i / 2 / 7) & 1 ? 32767 : -32768;
    uint8_t out[2048];
    CHECK(ima_encode(&e, sq, 2041, out, sizeof out) == 2048);
    memset(sq, 0, 2041 * 4);
    CHECK(ima_encode(&e, sq, 2041, out, sizeof out) == 2048);
    ima_encoder_free(&e); free(sq);
    printf(fails ? "test_ima: %d FAILED\n" : "test_ima: all passed\n", fails);
    return fails ? 1 : 0;
}
