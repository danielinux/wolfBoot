/* uart_drv_nrf52.c
 *
 * Driver for the back-end of the UART_FLASH module.
 *
 * Example implementation for nrf52, using UART0
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

#include <stdint.h>

#define BAUD_115200 0x01D7E000
#define UART0_BASE (0x40002000)

#define UART0_TASK_STARTRX *((volatile uint32_t *)(UART0_BASE + 0x000))
#define UART0_TASK_STARTTX *((volatile uint32_t *)(UART0_BASE + 0x008))
#define UART0_TASK_STOPTX  *((volatile uint32_t *)(UART0_BASE + 0x00C))
#define UART0_EVENT_ENDRX  *((volatile uint32_t *)(UART0_BASE + 0x110))
#define UART0_EVENT_ENDTX  *((volatile uint32_t *)(UART0_BASE + 0x120))
#define UART0_ENABLE       *((volatile uint32_t *)(UART0_BASE + 0x500))
#define UART0_RXD          *((volatile uint32_t *)(UART0_BASE + 0x518))
#define UART0_RXD_PTR      *((volatile uint32_t *)(UART0_BASE + 0x534))
#define UART0_RXD_MAXCOUNT *((volatile uint32_t *)(UART0_BASE + 0x538))
#define UART0_TXD_PTR      *((volatile uint32_t *)(UART0_BASE + 0x544))
#define UART0_TXD_MAXCOUNT *((volatile uint32_t *)(UART0_BASE + 0x548))
#define UART0_BAUDRATE     *((volatile uint32_t *)(UART0_BASE + 0x524))

void uart_init(void)
{
    UART0_BAUDRATE = BAUD_115200;
    UART0_ENABLE = 1;

}

int uart_tx(const uint8_t c)
{
    UART0_EVENT_ENDTX = 0;

    UART0_TXD_PTR = (uint32_t)(&c);
    UART0_TXD_MAXCOUNT = 1;
    UART0_TASK_STARTTX = 1;
    while(UART0_EVENT_ENDTX == 0)
        ;
    return 1;
}

int uart_rx(const uint8_t *c)
{
    UART0_EVENT_ENDTX = 0;

    UART0_RXD_PTR = (uint32_t)(c);
    UART0_RXD_MAXCOUNT = 1;
    UART0_TASK_STARTRX = 1;
    if (UART0_EVENT_ENDRX == 0)
        return 0;
    return 1;
}
