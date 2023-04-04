/* x86_fsp.c
 *
 * Copyright (C) 2023 wolfSSL Inc.
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

#include <wolfboot/wolfboot.h>
#include <stdint.h>

#ifdef __WOLFBOOT

#include "x86/pci.h"
#include "x86/ahci.h"
#include "x86/mptable.h"

#include "printf.h"

#include <sys/io.h>

#define AHCI_MMAP_ADDR 0x80000000
#define HBA_FIS_BASE   0x02200000
#define HBA_CLB_BASE   0x02300000
#define HBA_FIS_PORT_SIZE (sizeof(struct ahci_received_fis))

static void panic()
{
    while(1) {}
}

static uint32_t pci_read_reg(uint32_t bus, uint32_t dev, uint32_t func,
        uint32_t off)
{
    uint32_t address = PCI_CONFIG_ADDR(bus, dev, func, off);
    uint32_t data = 0xFFFFFFFF;
    outl(address, PCI_CONFIG_ADDR_PORT);
    data = inl(PCI_CONFIG_DATA_PORT);
    return data;
}

static void pci_write_reg(uint32_t bus, uint32_t dev, uint32_t func,
        uint32_t off, uint32_t val)
{
    uint32_t dst_addr = PCI_CONFIG_ADDR(bus, dev, func, off);
    outl(dst_addr, PCI_CONFIG_ADDR_PORT);
    outl(val, PCI_CONFIG_DATA_PORT);

}

static inline void ahci_set_bar(uint32_t bus, uint32_t dev, uint32_t func, uint32_t addr)
{
    pci_write_reg(bus, dev, func, AHCI_ABAR_OFFSET, addr);
}

static uint32_t ahci_enable(uint32_t bus, uint32_t dev, uint32_t fun)
{
    uint32_t reg;
    uint32_t bar;
    
    reg = pci_read_reg(bus, dev, fun, PCI_COMMAND_OFFSET);
    //reg |= PCI_COMMAND_INT_DIS | PCI_COMMAND_BUS_MASTER;
    reg |= PCI_COMMAND_BUS_MASTER;
    pci_write_reg(bus, dev, fun, PCI_COMMAND_OFFSET, reg);

    ahci_set_bar(bus, dev, fun, AHCI_MMAP_ADDR);


    reg = pci_read_reg(bus, dev, fun, PCI_COMMAND_OFFSET);
    reg |= PCI_COMMAND_MEM_SPACE;
    pci_write_reg(bus, dev, fun, PCI_COMMAND_OFFSET, reg);
    bar = pci_read_reg(bus, dev, fun, AHCI_ABAR_OFFSET);

    /* Set interrupt (manually for the moment) */
    reg = pci_read_reg(bus, dev, fun, PCI_INTR_OFFSET);
    wolfBoot_printf("Interrupt pin for AHCI controller: %02x\n", (reg >> 8) & 0xFF);
    //pci_write_reg(bus, dev, fun, PCI_INTR_OFFSET, (reg & 0xFFFFFF00 | 0x0b));
    //wolfBoot_printf("Setting interrupt line: 0x0B\n");

    return bar;
}

#define ATA_IDENTIFY_DEVICE 0xEC

static void sata_enable(uint32_t base) {
    uint32_t cap, ports_impl;
    uint32_t n_ports;
    uint32_t i;
    uint64_t data64;
    uint32_t data;


    if ((AHCI_HBA_GHC(base) & HBA_GHC_AE) == 0)
        AHCI_HBA_GHC(base) |= HBA_GHC_AE;
    wolfBoot_printf("AHCI memory mapped at %08x\r\n", base);

    /* Resetting the controller */
    AHCI_HBA_GHC(base) |= HBA_GHC_HR | HBA_GHC_IE;

    /* Wait until reset is complete */
    while ((AHCI_HBA_GHC(base) & HBA_GHC_HR) != 0)
        ;

    wolfBoot_printf("AHCI reset complete.\r\n");

    cap = AHCI_HBA_CAP(base);
    n_ports = (cap & 0x1F) + 1;

    ports_impl = AHCI_HBA_PI(base);

    wolfBoot_printf("AHCI: %d ports\r\n", n_ports);
    for (i = 0; i < AHCI_MAX_PORTS; i++) {
        if ((ports_impl & (1 << i)) != 0) {

            /* Check port count */
            if (n_ports-- == 0) {
                wolfBoot_printf("AHCI Error: Too many ports\r\n");
                return;
            }
            /* Initialize FIS address */
            AHCI_PxFB(base, i) = HBA_FIS_BASE + i * HBA_FIS_PORT_SIZE;
            AHCI_PxCLB(base, i) = HBA_CLB_BASE + i * HBA_FIS_PORT_SIZE;
            data = AHCI_PxCMD(base, i);

            if ((data & AHCI_PORT_CMD_CPD) != 0) {
                wolfBoot_printf("AHCI port %d: POD\r\n", i);
                AHCI_PxCMD(base, i) |= AHCI_PORT_CMD_POD;
            }

            if ((cap & AHCI_CAP_SSS) != 0) {
                wolfBoot_printf("AHCI port %d: Spinning\r\n", i);
                AHCI_PxCMD(base, i) |= AHCI_PORT_CMD_SUD;
            }

            /* Disable interrupts */
//            AHCI_PxIE(base, i) &= 0;
            /* Enable interrupts */
            AHCI_PxIE(base, i) |= (1 << 1);            

            /* Disable aggressive powersaving */
            AHCI_PxSCTL(base, i) |= (0x03 << 8);

            /* Enable FIS Rx DMA */
            AHCI_PxCMD(base, i) |= AHCI_PORT_CMD_FRE;

            wolfBoot_printf("AHCI Port %d configured\r\n", i);
            wolfBoot_printf("AHCI cmd reg: %08x\r\n", data);
            wolfBoot_printf("AHCI SSTS for port %d: %08x\r\n",
                    i, AHCI_PxSSTS(base, i));
        }
    }
}

static uint32_t ahci_detect(void)
{
    uint32_t bus,dev,fun;
    uint32_t vd_code, reg;
    uint16_t vendor_id, device_id, class_code;

    for (bus = 0; bus < 256; bus++) {
        for (dev = 0; dev < 64; dev++) {
            for (fun = 0; fun < 8; fun++) {
                vd_code = pci_read_reg(bus, dev, fun, PCI_VENDOR_ID_OFFSET);
                if (vd_code == 0xFFFFFFFF) {
                    /* No device here. */
                    continue;
                }
                device_id = (uint16_t)((vd_code >> 16) & 0xFFFF);
                vendor_id = (uint16_t)(vd_code & 0xFFFF);

                reg = pci_read_reg(bus, dev, fun, PCI_RID_CC_OFFSET);
                class_code = (uint16_t)((reg >> 8) & 0xFFFF);
                if (vendor_id == AHCI_VENDOR_ID && device_id == AHCI_DEVICE_ID) {
                    if (class_code == AHCI_CLASS_CODE) {
                        uint16_t ahci_vid;
                        reg = pci_read_reg(bus, dev, fun, AHCI_ID_OFFSET);
                        ahci_vid = (uint16_t)(reg & 0xFFFF);
                        if (ahci_vid != AHCI_VENDOR_ID) {
                            continue; /* Error accessing device */
                        } else {
                            return PCI_CONFIG_ADDR(bus, dev, fun, 0);
                        }
                    }
                }
            }
        }
    }
    return (0xFFFFFFFF); /* Nothing found. */
}


void hal_init(void)
{
    //uint32_t ahci_base = ahci_detect();
    uint32_t ahci_base = PCI_CONFIG_ADDR(0,31,2,0);
    uint32_t bus, dev, fun;
    uint32_t version;

    wolfBoot_printf("Setting MP TABLE\r\n");
    setup_mptable();

    if (ahci_base == 0xFFFFFFFF)
        panic();

    bus = PCI_BUS(ahci_base);
    dev = PCI_DEV(ahci_base);
    fun = PCI_FUN(ahci_base);
    ahci_enable(bus, dev, fun);
    version = AHCI_HBA_VS(AHCI_MMAP_ADDR);
    if (version < 0x10000 ) {
        panic();
    }
    sata_enable(AHCI_MMAP_ADDR);
}

void hal_prepare_boot(void)
{
}
#endif

int hal_flash_write(uint32_t address, const uint8_t *data, int len)
{
    return 0;
}

void hal_flash_unlock(void)
{
}

void hal_flash_lock(void)
{
}

int hal_flash_erase(uint32_t address, int len)
{
    return 0;
}

int wolfBoot_fallback_is_possible(void)
{
    return 0;

}

int wolfBoot_dualboot_candidate(void)
{
    return PART_BOOT;
}

void* hal_get_primary_address(void)
{
    return (void*)0;
}

void* hal_get_update_address(void)
{
  return (void*)0;
}

void *hal_get_dts_address(void)
{
    return 0;
}

void *hal_get_dts_update_address(void)
{
    return 0;
}

