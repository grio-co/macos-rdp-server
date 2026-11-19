#pragma once
/* GFX frame-acknowledgement flow control and adaptive bitrate (MS-RDPEGFX
 * 2.2.3.3 FRAME_ACKNOWLEDGE). Pure logic, no FreeRDP types, unit-tested.
 *
 * The sender counts frames in flight (sent - acked). Capture consults
 * rdp_fc_can_send() BEFORE encoding and skips the frame when the window is
 * full, so an already-encoded frame is never dropped (that would break the
 * H.264 reference chain). A client that stops acking cannot freeze output: after
 * a timeout the window is forgiven. queueDepth 0xFFFFFFFF (SUSPEND) turns the
 * throttle off. rdp_fc_rate_step() derives a bitrate scale from the pressure. */
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#define RDP_FC_SUSPEND_ACK 0xFFFFFFFFu
#define RDP_FC_RING 64

typedef struct {
    pthread_mutex_t lock;
    uint32_t maxInFlight;     /* window; default 3 */
    uint32_t stallTimeoutMs;  /* forgive an unacked window after this; default 1500 */
    uint32_t sentId, ackedId; /* last frame sent / acknowledged (wrap-safe) */
    bool     suspended;       /* client sent SUSPEND_FRAME_ACKNOWLEDGEMENT */
    uint64_t lastProgressMs;  /* last ack, or the send that opened the window */
    uint64_t sentMs[RDP_FC_RING];
    double   latencyEwmaMs;
    uint32_t lastQueueDepth;
    /* since the last rate step */
    uint32_t skips, acks, maxInFlightSeen;
    /* lifetime */
    uint64_t totalSkips, totalStalls, totalAcks;
    /* adaptive bitrate: scale of the target, in permille */
    uint32_t scalePermille;
    uint32_t calmSteps;
} RDPFlowControl;

void rdp_fc_init(RDPFlowControl *fc);
void rdp_fc_destroy(RDPFlowControl *fc);
/* Forget everything in flight (surfaces rebuilt: old frames will never be acked). */
void rdp_fc_reset(RDPFlowControl *fc);
void rdp_fc_on_send(RDPFlowControl *fc, uint32_t frameId, uint64_t nowMs);
void rdp_fc_on_ack(RDPFlowControl *fc, uint32_t frameId, uint32_t queueDepth,
                   uint64_t nowMs);
/* true: encode and send now. false: skip this capture (counted). */
bool rdp_fc_can_send(RDPFlowControl *fc, uint64_t nowMs);
uint32_t rdp_fc_in_flight(RDPFlowControl *fc);

/* Call every ~500 ms. Returns the new scale (permille of the target bitrate,
 * 150..1000); *changed is set when it differs from the previous step. The
 * stats it consumed (since the previous step) are returned in the out params
 * when non-NULL. */
uint32_t rdp_fc_rate_step(RDPFlowControl *fc, bool *changed,
                          uint32_t *maxInFlight, double *latencyMs);
