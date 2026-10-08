/* Application: a big lookup table nearly fills FLASH; initialised data
 * lives in RAM but is stored in FLASH (LMA != VMA). */
#include <stdint.h>

/* ~14 KiB of constant data: what's eating the flash? */
const uint8_t font_bitmap[14000] = {1, 2, 3};

uint32_t boot_count = 7;            /* .data: copied FLASH -> RAM at boot */
char device_name[32] = "linkmap-demo";
uint32_t rx_buffer[256];             /* .bss: zeroed, never stored in FLASH */

static uint32_t checksum(const uint8_t *p, uint32_t n) {
    uint32_t s = 0;
    for (uint32_t i = 0; i < n; i++) s += p[i];
    return s;
}

#ifdef V2
/* Version 2 of the firmware: a logging feature that grows FLASH and RAM. */
const char log_banner[600] = "linkmap-demo v2";
uint32_t log_ring[64];

static void log_init(void) {
    for (uint32_t i = 0; i < 64; i++) log_ring[i] = (uint32_t)log_banner[i % 16];
}
#endif

int main(void) {
    boot_count++;
#ifdef V2
    log_init();
#endif
    rx_buffer[0] = checksum(font_bitmap, sizeof font_bitmap) + (uint32_t)device_name[0];
    return 0;
}
