#include "protocol/RDPFlowControl.h"
#include <string.h>

#define SCALE_MIN 150u
#define SCALE_MAX 1000u
#define QUEUEING_HIGH_MS 80.0   /* ack latency this far above the base = congestion */
#define QUEUEING_LOW_MS  30.0
#define QUEUE_HIGH 3u
#define CALM_STEPS_TO_RAISE 3u
#define BASE_EPOCH_MS 10000u    /* the base latency forgets samples older than 10-20 s */
#define NO_LATENCY 1e12

void rdp_fc_init(RDPFlowControl *fc) {
    memset(fc, 0, sizeof *fc);
    pthread_mutex_init(&fc->lock, NULL);
    fc->maxInFlight = 3;
    fc->stallTimeoutMs = 1500;
    fc->scalePermille = SCALE_MAX;
    fc->epochMinMs[0] = fc->epochMinMs[1] = NO_LATENCY;
}

void rdp_fc_destroy(RDPFlowControl *fc) { pthread_mutex_destroy(&fc->lock); }

void rdp_fc_reset(RDPFlowControl *fc) {
    pthread_mutex_lock(&fc->lock);
    fc->ackedId = fc->sentId;
    fc->lastProgressMs = 0;
    pthread_mutex_unlock(&fc->lock);
}

static double base_latency_locked(const RDPFlowControl *fc) {
    return fc->epochMinMs[0] < fc->epochMinMs[1] ? fc->epochMinMs[0] : fc->epochMinMs[1];
}

/* Windowed minimum: the lower of this epoch's and the previous epoch's minimum,
 * so the base follows a path that got slower within 10-20 s. */
static void note_latency_locked(RDPFlowControl *fc, double lat, uint64_t nowMs) {
    if (!fc->epochStarted || nowMs - fc->epochStartMs >= BASE_EPOCH_MS) {
        fc->epochMinMs[0] = fc->epochStarted ? fc->epochMinMs[1] : NO_LATENCY;
        fc->epochMinMs[1] = NO_LATENCY;
        fc->epochStartMs = nowMs;
        fc->epochStarted = true;
    }
    if (lat < fc->epochMinMs[1]) fc->epochMinMs[1] = lat;
}

void rdp_fc_on_send(RDPFlowControl *fc, uint32_t frameId, uint64_t nowMs) {
    pthread_mutex_lock(&fc->lock);
    if ((uint32_t)(fc->sentId - fc->ackedId) == 0) fc->lastProgressMs = nowMs;
    /* Ids issued but never sent (a failed send) get this send's time, so the
     * oldest-frame age never reads a stale slot. */
    uint32_t gap = frameId - fc->sentId;
    if (gap > RDP_FC_RING) gap = RDP_FC_RING;
    for (uint32_t i = 1; i <= gap; i++) fc->sentMs[(uint32_t)(frameId - gap + i) % RDP_FC_RING] = nowMs;
    fc->sentId = frameId;
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
        uint64_t sent = fc->sentMs[frameId % RDP_FC_RING];
        double lat = nowMs > sent ? (double)(nowMs - sent) : 0.0;
        fc->latencyEwmaMs = fc->totalAcks == 0 ? lat : fc->latencyEwmaMs * 0.7 + lat * 0.3;
        note_latency_locked(fc, lat, nowMs);
        for (uint32_t i = 0; i < adv && i < RDP_FC_ACK_RING; i++)   /* cumulative ack */
            fc->ackMs[fc->ackHead++ % RDP_FC_ACK_RING] = nowMs;
        fc->ackedId = frameId;
        fc->lastProgressMs = nowMs;
        fc->acks++;
        fc->totalAcks++;
    }
    pthread_mutex_unlock(&fc->lock);
}

/* Bandwidth-delay product in frames, plus two, clamped to [maxInFlight, cap]. */
static uint32_t window_locked(const RDPFlowControl *fc, uint64_t nowMs) {
    uint32_t w = fc->maxInFlight;
    double base = base_latency_locked(fc);
    if (base < NO_LATENCY) {
        double spanMs = base * 2 > 1000.0 ? base * 2 : 1000.0;
        uint32_t n = 0, have = fc->ackHead < RDP_FC_ACK_RING ? fc->ackHead : RDP_FC_ACK_RING;
        for (uint32_t i = 0; i < have; i++)
            if ((double)(nowMs - fc->ackMs[i]) < spanMs) n++;
        double bdp = (double)n / spanMs * base;
        uint32_t bw = (uint32_t)bdp + (bdp > (uint32_t)bdp ? 1 : 0) + 2;
        if (bw > w) w = bw;
    }
    return w < RDP_FC_HARD_CAP ? w : RDP_FC_HARD_CAP;
}

uint32_t rdp_fc_window(RDPFlowControl *fc, uint64_t nowMs) {
    pthread_mutex_lock(&fc->lock);
    uint32_t w = window_locked(fc, nowMs);
    pthread_mutex_unlock(&fc->lock);
    return w;
}

bool rdp_fc_can_send(RDPFlowControl *fc, uint64_t nowMs) {
    bool ok = true;
    pthread_mutex_lock(&fc->lock);
    uint32_t inf = fc->sentId - fc->ackedId;
    if (!fc->suspended && inf > 0) {
        bool full = inf >= window_locked(fc, nowMs);
        if (full) {
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

double rdp_fc_base_latency(RDPFlowControl *fc) {
    pthread_mutex_lock(&fc->lock);
    double b = base_latency_locked(fc);
    pthread_mutex_unlock(&fc->lock);
    return b >= NO_LATENCY ? -1.0 : b;
}

uint32_t rdp_fc_rate_step(RDPFlowControl *fc, bool *changed,
                          uint32_t *maxInFlight, double *latencyMs, uint32_t *skips) {
    pthread_mutex_lock(&fc->lock);
    uint32_t old = fc->scalePermille;
    double base = base_latency_locked(fc);
    bool haveBase = base < NO_LATENCY;
    double queueing = haveBase ? fc->latencyEwmaMs - base : 0.0;
    /* Skips count only with queueing (or before any ack): a long path skips
     * while its window grows without being congested. */
    bool pressure = (fc->skips > 0 && (!haveBase || queueing > QUEUEING_LOW_MS)) ||
                    (fc->acks > 0 && queueing > QUEUEING_HIGH_MS) ||
                    (!fc->suspended && fc->lastQueueDepth > QUEUE_HIGH);
    bool calm = !pressure && (fc->acks == 0 || queueing < QUEUEING_LOW_MS);
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
