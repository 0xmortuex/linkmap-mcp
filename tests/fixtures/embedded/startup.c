/* Minimal Cortex-M startup: vector table + copy .data from FLASH to RAM. */
#include <stdint.h>

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;
int main(void);

void reset_handler(void) {
    uint32_t *src = &_sidata;
    for (uint32_t *dst = &_sdata; dst < &_edata;)
        *dst++ = *src++;
    for (uint32_t *dst = &_sbss; dst < &_ebss;)
        *dst++ = 0;
    main();
    for (;;) {}
}

void default_handler(void) { for (;;) {} }

__attribute__((section(".isr_vector"), used))
const void *vector_table[16] = {
    &_estack, (void *)reset_handler, (void *)default_handler, (void *)default_handler,
};
