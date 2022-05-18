/* boot_arm.c
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

#include "image.h"
#include "loader.h"
#include "wolfboot/wolfboot.h"
/*
 * These symbols are defined in the linker script
 * and represent the flash/memory areas for the
 * initialization and the bring-up
 */
extern unsigned int _start_text;
extern unsigned int _stored_data;
extern unsigned int _start_data;
extern unsigned int _end_data;
extern unsigned int _start_bss;
extern unsigned int _end_bss;
extern uint32_t *END_STACK;

/* main() is defined in loader.c */
extern void main(void);


/* dummmy mpu calls */
#define mpu_init() do{}while(0)
#define mpu_off() do{}while(0)


/*!
    \ingroup InterruptVectors

    \brief Entry point after MCU reset. This start-up routine is in charge of initializing
        the sections to run wolfBoot. After memory is initialized, the control is passed to main().
        This procedure never returns (main never returns).
    \sa main

*/
void isr_reset(void) {
    register unsigned int *src, *dst;
    /* init stack pointers and SRAM */
    /* Copy the .data section from flash to RAM. */
    src = (unsigned int *) &_stored_data;
    dst = (unsigned int *) &_start_data;
    while (dst < (unsigned int *)&_end_data) {
        *dst = *src;
        dst++;
        src++;
    }
    /* Initialize the BSS section to 0 */
    dst = &_start_bss;
    while (dst < (unsigned int *)&_end_bss) {
        *dst = 0U;
        dst++;
    }
    mpu_init();

    /* Run the program! */
    main();
}

/*!
    \ingroup InterruptVectors

    \brief Interrupt service routine for hardware faults. By default, it will panic().
    \sa isr_reset
    \sa wolfBoot_panic
*/
void isr_fault(void)
{
    /* Panic. */
    wolfBoot_panic();
}


/*!
    \ingroup InterruptVectors
    \brief Empty interrupt service routine to ignore unmapped/inactive interrupts.
*/
void isr_empty(void)
{
    /* Ignore unmapped event and continue */
}

/* NULL ISR */
#   define isr_securefault 0

/* VTOR Register is at the same address on all Cortex-M */
#define VTOR (*(volatile uint32_t *)(0xE000ED08))

/* Global variable holding the entry point of the staged firmware */
static void  *app_entry;

/* Global variable holding the initial stack pointer for the staged firmware */
static uint32_t app_end_stack;


/*!
    \ingroup boot_arm

    \brief This is the main staging function.
        It performs the following actions:
        - globally disable interrupts
        - update the Interrupt Vector using the address of the app
        - Set the initial stack pointer and the offset of the app
        - Change the stack pointer
        - Call the application entry point

    \sa wolfBoot_start
*/

void RAMFUNCTION do_boot(const uint32_t *app_offset)
{

    mpu_off();
    /* Disable interrupts */
    asm volatile("cpsid i");
    /* Update IV */
    VTOR = ((uint32_t)app_offset);
    /* Get stack pointer, entry point */
    app_end_stack = (*((uint32_t *)(app_offset)));
    app_entry = (void *)(*((uint32_t *)(app_offset + 1)));

    /* Update stack pointer */
    asm volatile("msr msp, %0" ::"r"(app_end_stack));
    asm volatile("cpsie i");

    /* Unconditionally jump to app_entry */
    asm volatile("mov pc, %0" ::"r"(app_entry));
}

#   define isr_NMI isr_empty

/* Interrupt vector table, stored at the beginning of wolfBoot image.
 *
 */
__attribute__ ((section(".isr_vector")))
void (* const IV[])(void) =
{
	(void (*)(void))(&END_STACK),
	isr_reset,                   // Reset
	isr_NMI,                     // NMI
	isr_fault,                   // HardFault
	isr_fault,                   // MemFault
	isr_fault,                   // BusFault
	isr_fault,                   // UsageFault
	isr_securefault,             // SecureFault on M23/33, reserved otherwise (0)
    0,                           // reserved
    0,                           // reserved
    0,                           // reserved
	isr_empty,                   // SVC
	isr_empty,                   // DebugMonitor
	0,                           // reserved
	isr_empty,                   // PendSV
	isr_empty,                   // SysTick
};
