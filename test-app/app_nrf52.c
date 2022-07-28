/* nrf52.c
 *
 * Copyright (C) 2021 wolfSSL Inc.
 *
 * This file is part of wolfBoot.
 *
 * wolfBoot is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfBoot is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "wolfboot/wolfboot.h"
#include "uart_drv.h"


#define GPIO_BASE (0x50000000)
#define GPIO_OUT        *((volatile uint32_t *)(GPIO_BASE + 0x504))
#define GPIO_OUTSET     *((volatile uint32_t *)(GPIO_BASE + 0x508))
#define GPIO_OUTCLR     *((volatile uint32_t *)(GPIO_BASE + 0x50C))
#define GPIO_PIN_CNF     ((volatile uint32_t *)(GPIO_BASE + 0x700)) // Array


#define BAUD_115200 0x01D7E000

#define UART0_BASE (0x40002000)
#define UART0_TASK_STARTTX *((volatile uint32_t *)(UART0_BASE + 0x008))
#define UART0_TASK_STOPTX  *((volatile uint32_t *)(UART0_BASE + 0x00C))
#define UART0_EVENT_ENDTX  *((volatile uint32_t *)(UART0_BASE + 0x120))
#define UART0_ENABLE       *((volatile uint32_t *)(UART0_BASE + 0x500))
#define UART0_TXD_PTR      *((volatile uint32_t *)(UART0_BASE + 0x544))
#define UART0_TXD_MAXCOUNT *((volatile uint32_t *)(UART0_BASE + 0x548))
#define UART0_BAUDRATE     *((volatile uint32_t *)(UART0_BASE + 0x524))

/* Matches all keys:
 *    - chacha (32 + 12)
 *    - aes128 (16 + 16)
 *    - aes256 (32 + 16)
 */
/* Longest key possible: AES256 (32 key + 16 IV = 48) */
char enc_key[] = "0123456789abcdef0123456789abcdef"
		 "0123456789abcdef";

static void gpiotoggle(uint32_t pin)
{
    uint32_t reg_val = GPIO_OUT;
    GPIO_OUTCLR = reg_val & (1 << pin);
    GPIO_OUTSET = (~reg_val) & (1 << pin);
}



static const char START='*';
void main(void)
{
    //uint32_t pin = 19;
    uint32_t pin = 6;
    int i;
    uint32_t version = 0, updv=0;
    uint8_t *v_array = (uint8_t *)&version;
    uart_init(115200, 8, 'N', 1);
    GPIO_PIN_CNF[pin] = 1; /* Output */

    version = wolfBoot_current_firmware_version();
    updv = wolfBoot_update_firmware_version();
    uart_tx('*');
    uart_tx((version >> 24) & 0xFF);
    uart_tx((version >> 16) & 0xFF);
    uart_tx((version >> 8) & 0xFF);
    uart_tx(version & 0xFF);
    if ((version == 1) && (updv != 8)) {
        uint32_t sz;
        gpiotoggle(pin);
#if EXT_ENCRYPTED
        wolfBoot_set_encrypt_key((uint8_t *)enc_key,(uint8_t *)(enc_key +  32));
#endif
        wolfBoot_update_trigger();
        gpiotoggle(pin);
    } else {
        if (version != 7)
            wolfBoot_success();
    }

    uart_tx(START);
    for (i = 3; i >= 0; i--) {
        uart_tx(v_array[i]);
    }
    while(1) {
        for (i = 0; i < 800000; i++)  // Wait, wait, wait.
              asm volatile ("nop");
    }
}
