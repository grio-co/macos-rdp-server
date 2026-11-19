/* clang -Wall -Wextra -I. tests/test_input_logic.c -o /tmp/t && /tmp/t */
#include "input/InputLogic.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    assert(il_wheel_rotation(0x078) == 120);
    assert(il_wheel_rotation(0x188) == -120);
    assert(il_wheel_rotation(0x1FF) == -1);
    assert(il_wheel_rotation(0x0FF) == 255);

    double acc = 0; int total = 0;
    for (int i = 0; i < 120; i++) total += il_wheel_accumulate(&acc, 1);
    assert(total == 48);                       /* 120 units == one notch */
    acc = 0;
    assert(il_wheel_accumulate(&acc, 1) == 0); /* tiny delta: no full line */
    assert(il_wheel_accumulate(&acc, -120) == -47); /* 0.4 px carried */
    acc = 0; assert(il_wheel_accumulate(&acc, -120) == -48);

    ILClickTracker t; il_click_init(&t);
    assert(il_click_down(&t, 0, 1.0, 0.5, 100, 100) == 1);
    assert(il_click_down(&t, 0, 1.3, 0.5, 102, 99) == 2);
    assert(il_click_down(&t, 0, 1.6, 0.5, 102, 99) == 3);
    assert(il_click_down(&t, 1, 1.7, 0.5, 102, 99) == 1);   /* other button */
    assert(il_click_down(&t, 1, 1.8, 0.5, 120, 99) == 1);   /* moved far */
    assert(il_click_down(&t, 1, 3.0, 0.5, 120, 99) == 1);   /* too slow */

    assert(il_event_flags(0, false) == 0);
    assert(il_event_flags(IL_DEV_LSHIFT | IL_DEV_RCMD, true) ==
           (IL_DEV_LSHIFT | IL_DEV_RCMD | IL_FLAG_SHIFT | IL_FLAG_COMMAND | IL_FLAG_ALPHASHIFT));
    assert(il_event_flags(IL_DEV_RCTL, false) == (IL_DEV_RCTL | IL_FLAG_CONTROL));
    assert(il_modifier_device_bit(IL_VK_ALT_R) == IL_DEV_RALT && il_modifier_device_bit(0) == 0);
    puts("ok");
    return 0;
}
