/* ahci.h
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

#ifndef X86_AHCI_MEM
#define X86_AHCI_MEM

#define AHCI_VENDOR_ID      0x8086
//#define AHCI_DEVICE_ID      0x282a
#define AHCI_DEVICE_ID      0x2922 /* ICH9 controller */
#define AHCI_CLASS_ID       0x01
#define AHCI_SUBCLASS_ID    0x06
#define AHCI_CLASS_CODE     0x0601
#define AHCI_PROG_IF        0x01

#define AHCI_ID_OFFSET       0x00
#define AHCI_CMD_OFFSET      0x04
#define AHCI_STS_OFFSET      0x06
#define AHCI_ABAR_OFFSET     0x24

#define AHCI_MAX_PORTS 32


#define AHCI_HBA_CAP(base)  (*(volatile uint32_t *)(base + 0x00))
#define AHCI_HBA_GHC(base)  (*(volatile uint32_t *)(base + 0x04))
#define AHCI_HBA_IS(base)  (*(volatile uint32_t *)(base + 0x08))
#define AHCI_HBA_PI(base)  (*(volatile uint32_t *)(base + 0x0C))
#define AHCI_HBA_VS(base)  (*(volatile uint32_t *)(base + 0x10))
#define AHCI_HBA_CCC_CTL(base)  (*(volatile uint32_t *)(base + 0x14))
#define AHCI_HBA_CCC_PORTS (*(volatile uint32_t *)(base + 0x18))
#define AHCI_HBA_EM_LOC    (*(volatile uint32_t *)(base + 0x1C))
#define AHCI_HBA_EM_CTL    (*(volatile uint32_t *)(base + 0x20))
#define AHCI_HBA_CAP2      (*(volatile uint32_t *)(base + 0x24))
#define AHCI_HBA_BOHC      (*(volatile uint32_t *)(base + 0x28))

#define AHCI_PORT_START 0x100
#define AHCI_PORT_SIZE  0x80
#define AHCI_PORT_SSTS_OFFSET 0x28

#define AHCI_PORT_REG_START(base,port) (*(volatile uint32_t *)(base + AHCI_PORT_START + \
            (port * AHCI_PORT_SIZE)))

#define AHCI_SSTS(base, port) (*(volatile uint32_t *)(base + AHCI_PORT_START + \
            (port * AHCI_PORT_SIZE) + AHCI_PORT_SSTS_OFFSET))

#define HBA_GHC_AE     (1 << 31) /* AHCI ENABLE */
#define HBA_GHC_HR     (1 << 0)  /* HARD RESET */







#endif
