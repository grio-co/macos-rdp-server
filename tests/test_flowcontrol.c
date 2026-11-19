/* protocol/RDPFlowControl.c: ack window, stall recovery, suspend, adaptive rate. */
#include "protocol/RDPFlowControl.h"
#include <stdio.h>
#include <stdlib.h>

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

int main(void) {
    RDPFlowControl fc; rdp_fc_init(&fc);
    uint64_t t = 1000;

    /* window of 3 */
    for (uint32_t i = 1; i <= 3; i++) { CHECK(rdp_fc_can_send(&fc, t)); rdp_fc_on_send(&fc, i, t); }
    CHECK(rdp_fc_in_flight(&fc) == 3);
    CHECK(!rdp_fc_can_send(&fc, t + 10));
    rdp_fc_on_ack(&fc, 1, 2, t + 20);
    CHECK(rdp_fc_can_send(&fc, t + 20));
    rdp_fc_on_send(&fc, 4, t + 20);
    CHECK(!rdp_fc_can_send(&fc, t + 21));
    /* stale / future acks ignored */
    rdp_fc_on_ack(&fc, 1, 0, t + 22);
    rdp_fc_on_ack(&fc, 99, 0, t + 22);
    CHECK(rdp_fc_in_flight(&fc) == 3);
    /* cumulative ack */
    rdp_fc_on_ack(&fc, 4, 0, t + 30);
    CHECK(rdp_fc_in_flight(&fc) == 0);

    /* stall: client stops acking, output resumes after the timeout */
    t = 5000;
    for (uint32_t i = 5; i <= 7; i++) rdp_fc_on_send(&fc, i, t);
    CHECK(!rdp_fc_can_send(&fc, t + 1000));
    CHECK(rdp_fc_can_send(&fc, t + 1600));
    CHECK(rdp_fc_in_flight(&fc) == 0 && fc.totalStalls == 1);

    /* suspend: never throttles */
    for (uint32_t i = 8; i <= 12; i++) rdp_fc_on_send(&fc, i, t + 2000);
    rdp_fc_on_ack(&fc, 8, RDP_FC_SUSPEND_ACK, t + 2001);
    CHECK(rdp_fc_can_send(&fc, t + 2002));
    rdp_fc_on_ack(&fc, 12, 0, t + 2003);   /* resumes acking */
    CHECK(!fc.suspended);

    /* wraparound */
    RDPFlowControl w; rdp_fc_init(&w);
    w.sentId = w.ackedId = 0xFFFFFFFEu;
    rdp_fc_on_send(&w, 0xFFFFFFFFu, 100); rdp_fc_on_send(&w, 0, 100); rdp_fc_on_send(&w, 1, 100);
    CHECK(rdp_fc_in_flight(&w) == 3);
    rdp_fc_on_ack(&w, 0, 0, 110);
    CHECK(rdp_fc_in_flight(&w) == 1);
    rdp_fc_destroy(&w);

    /* adaptive rate: pressure lowers, calm raises back */
    RDPFlowControl r; rdp_fc_init(&r);
    bool ch; uint32_t s;
    for (uint32_t i = 1; i <= 3; i++) rdp_fc_on_send(&r, i, 0);
    (void)rdp_fc_can_send(&r, 10);          /* a skip */
    s = rdp_fc_rate_step(&r, &ch, NULL, NULL);
    CHECK(ch && s == 700);
    (void)rdp_fc_can_send(&r, 20);
    s = rdp_fc_rate_step(&r, &ch, NULL, NULL);
    CHECK(s == 490);
    for (int i = 0; i < 30; i++) { (void)rdp_fc_can_send(&r, 30); s = rdp_fc_rate_step(&r, &ch, NULL, NULL); }
    CHECK(s == 150);                         /* floor */
    rdp_fc_on_ack(&r, 3, 0, 40);             /* link recovers: fast acks */
    for (int i = 0; i < 60; i++) {
        uint32_t id = r.sentId + 1;
        rdp_fc_on_send(&r, id, 50 + i); rdp_fc_on_ack(&r, id, 0, 51 + i);
        s = rdp_fc_rate_step(&r, &ch, NULL, NULL);
    }
    CHECK(s == 1000);                        /* back at target */
    /* high ack latency alone lowers it */
    for (int i = 0; i < 5; i++) {
        uint32_t id = r.sentId + 1;
        rdp_fc_on_send(&r, id, 1000); rdp_fc_on_ack(&r, id, 0, 1400);
    }
    s = rdp_fc_rate_step(&r, &ch, NULL, NULL);
    CHECK(ch && s < 1000);
    rdp_fc_destroy(&r);
    rdp_fc_destroy(&fc);

    printf(fails ? "test_flowcontrol: %d FAILED\n" : "test_flowcontrol: all passed\n", fails);
    return fails ? 1 : 0;
}
