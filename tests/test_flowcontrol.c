/* protocol/RDPFlowControl.c: delay-based ack window, hard cap, stall recovery,
 * suspend, wraparound, and the adaptive rate (congestion lowers it; a long but
 * uncongested path does not). */
#include "protocol/RDPFlowControl.h"
#include <stdio.h>
#include <stdlib.h>

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

typedef struct {
    uint32_t skipped, maxInFlight, scale;
} LinkResult;

enum { Q = 1024 };
typedef struct {               /* the simulated client: acks in flight */
    struct { uint32_t id; uint64_t due; } q[Q];
    int qh, qt;
    uint64_t lastDue;
} Link;
static Link link_state;

/* Captures every `interval` ms for `ms` ms. The client acks a frame `lat` ms
 * after it was sent, and handles at most one frame per `service` ms (so a
 * service time above the interval is a link or client that cannot keep up).
 * Runs the rate step every 500 ms. 1 ms resolution. */
static LinkResult run_link(RDPFlowControl *fc, uint64_t *t, uint32_t ms, uint32_t interval,
                           uint32_t lat, uint32_t service) {
    Link *L = &link_state;     /* persists across calls on the same fc */
    uint64_t end = *t + ms;
    LinkResult r = { 0, 0, fc->scalePermille };
    for (; *t < end; (*t)++) {
        while (L->qh != L->qt && L->q[L->qh].due <= *t) {
            rdp_fc_on_ack(fc, L->q[L->qh].id, 0, *t);
            L->qh = (L->qh + 1) % Q;
        }
        if (*t % interval == 0) {
            if (rdp_fc_can_send(fc, *t)) {
                uint32_t id = fc->sentId + 1;
                rdp_fc_on_send(fc, id, *t);
                uint64_t due = *t + lat;
                if (L->lastDue && due < L->lastDue + service) due = L->lastDue + service;
                L->lastDue = due;
                L->q[L->qt].id = id; L->q[L->qt].due = due; L->qt = (L->qt + 1) % Q;
                uint32_t inf = rdp_fc_in_flight(fc);
                if (inf > r.maxInFlight) r.maxInFlight = inf;
            } else {
                r.skipped++;
            }
        }
        if (*t % 500 == 499) r.scale = rdp_fc_rate_step(fc, NULL, NULL, NULL, NULL);
    }
    return r;
}

int main(void) {
    /* Bootstrap: before any ack the window is a fixed 3 frames. */
    RDPFlowControl fc; rdp_fc_init(&fc);
    uint64_t t = 1000;
    for (uint32_t i = 1; i <= 3; i++) { CHECK(rdp_fc_can_send(&fc, t)); rdp_fc_on_send(&fc, i, t); }
    CHECK(rdp_fc_in_flight(&fc) == 3);
    CHECK(!rdp_fc_can_send(&fc, t + 10));
    CHECK(rdp_fc_base_latency(&fc) < 0);
    /* First ack: base latency 20 ms, one frame per second delivered: the
     * bandwidth-delay product is tiny, so the window stays at 3. */
    rdp_fc_on_ack(&fc, 1, 0, t + 20);
    CHECK(rdp_fc_base_latency(&fc) == 20.0);
    CHECK(rdp_fc_window(&fc, t + 20) == 3);
    rdp_fc_on_send(&fc, 4, t + 20);
    CHECK(!rdp_fc_can_send(&fc, t + 21));
    /* stale / future acks ignored, cumulative ack */
    rdp_fc_on_ack(&fc, 1, 0, t + 122);
    rdp_fc_on_ack(&fc, 99, 0, t + 122);
    CHECK(rdp_fc_in_flight(&fc) == 3);
    rdp_fc_on_ack(&fc, 4, 0, t + 130);
    CHECK(rdp_fc_in_flight(&fc) == 0);
    /* A failed send leaves an id gap; a later cumulative ack clears it. */
    rdp_fc_on_send(&fc, 6, t + 200);         /* id 5 was issued but never sent */
    CHECK(rdp_fc_in_flight(&fc) == 2);
    rdp_fc_on_ack(&fc, 6, 0, t + 220);
    CHECK(rdp_fc_in_flight(&fc) == 0);
    rdp_fc_destroy(&fc);

    /* Hard cap: 100 fps over a 1 s path would want ~100 frames in flight. */
    RDPFlowControl h; rdp_fc_init(&h); link_state = (Link){0};
    uint64_t th = 0;
    LinkResult hr = run_link(&h, &th, 20000, 10, 1000, 0);
    CHECK(hr.maxInFlight == RDP_FC_HARD_CAP);
    rdp_fc_destroy(&h);

    /* Stall: the client stops acking; output resumes after the timeout. */
    RDPFlowControl s; rdp_fc_init(&s);
    for (uint32_t i = 1; i <= 3; i++) rdp_fc_on_send(&s, i, 5000);
    CHECK(!rdp_fc_can_send(&s, 6000));
    CHECK(rdp_fc_can_send(&s, 6600));
    CHECK(rdp_fc_in_flight(&s) == 0 && s.totalStalls == 1);
    /* Suspend: never throttles. */
    for (uint32_t i = 4; i <= 12; i++) rdp_fc_on_send(&s, i, 7000);
    rdp_fc_on_ack(&s, 4, RDP_FC_SUSPEND_ACK, 7001);
    CHECK(rdp_fc_can_send(&s, 7002));
    rdp_fc_on_ack(&s, 12, 0, 7003);          /* resumes acking */
    CHECK(!s.suspended);
    rdp_fc_destroy(&s);

    /* Wraparound. */
    RDPFlowControl w; rdp_fc_init(&w);
    w.sentId = w.ackedId = 0xFFFFFFFEu;
    rdp_fc_on_send(&w, 0xFFFFFFFFu, 100); rdp_fc_on_send(&w, 0, 100); rdp_fc_on_send(&w, 1, 100);
    CHECK(rdp_fc_in_flight(&w) == 3);
    rdp_fc_on_ack(&w, 0, 0, 110);
    CHECK(rdp_fc_in_flight(&w) == 1);
    rdp_fc_destroy(&w);

    /* LAN: 30 fps, 10 ms acks: nothing skipped, full bitrate. */
    RDPFlowControl lan; rdp_fc_init(&lan); link_state = (Link){0};
    t = 0;
    LinkResult r = run_link(&lan, &t, 5000, 33, 10, 0);
    CHECK(r.skipped == 0 && r.scale == 1000);
    rdp_fc_destroy(&lan);

    /* WAN: 30 fps over a 300 ms but uncongested path. The window grows with the
     * delivery rate (skips meanwhile, but no bitrate cut: no queueing); then ~10
     * frames stay in flight, nothing is skipped, full bitrate. */
    RDPFlowControl wan; rdp_fc_init(&wan); link_state = (Link){0};
    t = 0;
    r = run_link(&wan, &t, 5000, 33, 300, 0);
    printf("  wan ramp: skipped %u, peak in flight %u, scale %u\n", r.skipped, r.maxInFlight, r.scale);
    CHECK(r.skipped > 0 && r.scale == 1000);
    r = run_link(&wan, &t, 10000, 33, 300, 0);
    printf("  wan: skipped %u, peak in flight %u, scale %u\n", r.skipped, r.maxInFlight, r.scale);
    CHECK(r.skipped == 0);
    CHECK(r.maxInFlight >= 8 && r.maxInFlight < RDP_FC_HARD_CAP);
    CHECK(r.scale == 1000);
    rdp_fc_destroy(&wan);

    /* Congested: the client handles one frame per 100 ms while capture runs at
     * 30 fps. Frames are skipped, in-flight stays bounded, the bitrate drops. */
    RDPFlowControl slow; rdp_fc_init(&slow); link_state = (Link){0};
    t = 0;
    r = run_link(&slow, &t, 5000, 33, 10, 100);
    printf("  congested: skipped %u, peak in flight %u, scale %u\n", r.skipped, r.maxInFlight, r.scale);
    CHECK(r.skipped > 50);
    CHECK(r.maxInFlight <= 5);
    CHECK(r.scale < 500);
    rdp_fc_destroy(&slow);

    /* Rate: skips lower it to the floor; fast acks bring it back. */
    RDPFlowControl q; rdp_fc_init(&q);
    bool ch; uint32_t sc;
    for (uint32_t i = 1; i <= 3; i++) rdp_fc_on_send(&q, i, 0);
    (void)rdp_fc_can_send(&q, 10);           /* a skip */
    sc = rdp_fc_rate_step(&q, &ch, NULL, NULL, NULL);
    CHECK(ch && sc == 700);
    (void)rdp_fc_can_send(&q, 20);
    sc = rdp_fc_rate_step(&q, &ch, NULL, NULL, NULL);
    CHECK(sc == 490);
    for (int i = 0; i < 30; i++) { (void)rdp_fc_can_send(&q, 30); sc = rdp_fc_rate_step(&q, &ch, NULL, NULL, NULL); }
    CHECK(sc == 150);                         /* floor */
    rdp_fc_on_ack(&q, 3, 0, 40);
    for (int i = 0; i < 60; i++) {
        uint32_t id = q.sentId + 1;
        rdp_fc_on_send(&q, id, 50 + i); rdp_fc_on_ack(&q, id, 0, 51 + i);
        sc = rdp_fc_rate_step(&q, &ch, NULL, NULL, NULL);
    }
    CHECK(sc == 1000);
    /* Queueing (latency well above the base) lowers it... */
    for (int i = 0; i < 5; i++) {
        uint32_t id = q.sentId + 1;
        rdp_fc_on_send(&q, id, 1000); rdp_fc_on_ack(&q, id, 0, 1400);
    }
    sc = rdp_fc_rate_step(&q, &ch, NULL, NULL, NULL);
    CHECK(ch && sc < 1000);
    rdp_fc_destroy(&q);
    /* ...but a constant long latency (the path's base) does not. */
    RDPFlowControl c; rdp_fc_init(&c);
    for (uint32_t id = 1; id <= 20; id++) { rdp_fc_on_send(&c, id, id * 33); rdp_fc_on_ack(&c, id, 0, id * 33 + 400); }
    sc = rdp_fc_rate_step(&c, &ch, NULL, NULL, NULL);
    CHECK(!ch && sc == 1000);
    rdp_fc_destroy(&c);

    printf(fails ? "test_flowcontrol: %d FAILED\n" : "test_flowcontrol: all passed\n", fails);
    return fails ? 1 : 0;
}
