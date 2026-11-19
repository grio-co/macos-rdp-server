#include "protocol/RDPFlowControl.h"
#include <string.h>

#define SCALE_MIN 150u
#define SCALE_MAX 1000u
#define LATENCY_HIGH_MS 150.0
#define LATENCY_LOW_MS  80.0
#define QUEUE_HIGH 3u
#define CALM_STEPS_TO_RAISE 3u

void rdp_fc_init(RDPFlowControl *fc) {
    memset(fc, 0, sizeof *fc);
    pthread_mutex_init(&fc->lock, NULL);
    fc->maxInFlight = 3;
    fc->stallTimeoutMs = 1500;
    fc->scalePermille = SCALE_MAX;
}

void rdp_fc_destroy(RDPFlowControl *fc) { pthread_mutex_destroy(&fc->lock); }

void rdp_fc_reset(RDPFlowControl *fc) {
    pthread_mutex_lock(&fc->lock);
    fc->ackedId = fc->sentId;
    fc->lastProgressMs = 0;
    pthread_mutex_unlock(&fc->lock);
}

void rdp_fc_on_send(RDPFlowControl *fc, uint32_t frameId, uint64_t nowMs) {
    pthread_mutex_lock(&fc->lock);
    if ((uint32_t)(fc->sentId - fc->ackedId) == 0) fc->lastProgressMs = nowMs;
    fc->sentId = frameId;
    fc->sentMs[frameId % RDP_FC_RING] = nowMs;
    uint32_t inf = fc->sentId - fc->ackedId;
    if (inf > fc->maxInFlightSeen) fc->maxInFlightSeen = inf;
    pthread_mutex_unlock(&fc->lock);
}

void rdp_fc_on_ack(RDPFlowControl *fc, uint32_t frameId, uint32_t queueDepth,
                   uint64_t nowMs) {
    pthread_mutex_lock(&fc->lock);
    fc->suspended = (queueDepth == RDP_FC_SUSPEND_ACK);
    if (!fc->suspended) fc->lastQueueDepth = queueDepth;
    /* Ignore acks for frames we never sent or already counted. */
    uint32_t adv = frameId - fc->ackedId;
    if (adv != 0 && adv <= (uint32_t)(fc->sentId - fc->ackedId)) {
        double lat = (double)(nowMs - fc->sentMs[frameId % RDP_FC_RING]);
        if (lat < 0) lat = 0;
        fc->latencyEwmaMs = fc->totalAcks == 0
                          ? lat : fc->latencyEwmaMs * 0.7 + lat * 0.3;
        fc->ackedId = frameId;
        fc->lastProgressMs = nowMs;
        fc->acks++;
        fc->totalAcks++;
    }
    pthread_mutex_unlock(&fc->lock);
}

bool rdp_fc_can_send(RDPFlowControl *fc, uint64_t nowMs) {
    bool ok = true;
    pthread_mutex_lock(&fc->lock);
    if (!fc->suspended) {
        uint32_t inf = fc->sentId - fc->ackedId;
        if (inf >= fc->maxInFlight) {
            if (nowMs - fc->lastProgressMs >= fc->stallTimeoutMs) {
                /* Client went quiet: resume. Nothing was dropped after encoding,
                 * so its reference chain is intact. */
                fc->ackedId = fc->sentId;
                fc->totalStalls++;
            } else {
                ok = false;
                fc->skips++;
                fc->totalSkips++;
            }
        }
    }
    pthread_mutex_unlock(&fc->lock);
    return ok;
}

uint32_t rdp_fc_in_flight(RDPFlowControl *fc) {
    pthread_mutex_lock(&fc->lock);
    uint32_t n = fc->sentId - fc->ackedId;
    pthread_mutex_unlock(&fc->lock);
    return n;
}

uint32_t rdp_fc_rate_step(RDPFlowControl *fc, bool *changed,
                          uint32_t *maxInFlight, double *latencyMs, uint32_t *skips) {
    pthread_mutex_lock(&fc->lock);
    uint32_t old = fc->scalePermille;
    bool pressure = fc->skips > 0 ||
                    (fc->acks > 0 && fc->latencyEwmaMs > LATENCY_HIGH_MS) ||
                    (!fc->suspended && fc->lastQueueDepth > QUEUE_HIGH);
    bool calm = !pressure && (fc->acks == 0 || fc->latencyEwmaMs < LATENCY_LOW_MS);
    if (pressure) {
        fc->scalePermille = fc->scalePermille * 7 / 10;
        if (fc->scalePermille < SCALE_MIN) fc->scalePermille = SCALE_MIN;
        fc->calmSteps = 0;
    } else if (calm) {
        if (++fc->calmSteps >= CALM_STEPS_TO_RAISE && fc->scalePermille < SCALE_MAX) {
            fc->scalePermille = fc->scalePermille * 115 / 100 + 1;
            if (fc->scalePermille > SCALE_MAX) fc->scalePermille = SCALE_MAX;
        }
    }
    if (maxInFlight) *maxInFlight = fc->maxInFlightSeen;
    if (latencyMs) *latencyMs = fc->latencyEwmaMs;
    if (skips) *skips = fc->skips;
    fc->skips = 0; fc->acks = 0; fc->maxInFlightSeen = 0;
    uint32_t s = fc->scalePermille;
    pthread_mutex_unlock(&fc->lock);
    if (changed) *changed = (s != old);
    return s;
}
