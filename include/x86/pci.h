/* pci_mem.h
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

#ifndef X86_PCI_INCLUDED
#define X86_PCI_INCLUDED

#define PCI_CONFIG_ADDR_PORT 0xCF8
#define PCI_CONFIG_DATA_PORT 0xCFC
#define PCI_VENDOR_ID_OFFSET 0x00
#define PCI_DEVICE_ID_OFFSET 0x02
#define PCI_COMMAND_OFFSET   0x04
#define PCI_RID_CC_OFFSET 0x08 /* Programming interface, Rev. ID and class code */
#define PCI_HEADER_TYPE_OFFSET 0x0E
#define PCI_BAR_OFFSET (0x10)
#define PCI_BAR5_OFFSET 0x24
#define PCI_BAR5_MASK (~0x3)
#define PCI_HEADER_TYPE_MULTIFUNC_MASK 0x80
#define PCI_HEADER_TYPE_TYPE_MASK 0x7F
#define PCI_CLASS_MASS_STORAGE 0x01
#define PCI_SUBCLASS_SATA 0x06
#define PCI_INTERFACE_AHCI 0x01


/* Shifts & masks for CONFIG_ADDRESS register */

#define PCI_CONFIG_ADDRESS_ENABLE_BIT_SHIFT 31
#define PCI_CONFIG_ADDRESS_BUS_SHIFT    16
#define PCI_CONFIG_ADDRESS_DEVICE_SHIFT 11
#define PCI_CONFIG_ADDRESS_FUNCTION_SHIFT 8
#define PCI_CONFIG_ADDRESS_OFFSET_MASK 0xFF

/* COMMAND bits */

#define PCI_COMMAND_INT_DIS         (1 << 10)
#define PCI_COMMAND_FAST_B2B_EN     (1 << 9)
#define PCI_COMMAND_SERR_EN         (1 << 8)
#define PCI_COMMAND_PE_RESP         (1 << 6)
#define PCI_COMMAND_VGASNOOP        (1 << 5)
#define PCI_COMMAND_MW_INV_EN       (1 << 4)
#define PCI_COMMAND_SPECIAL_CYCLE   (1 << 3)
#define PCI_COMMAND_BUS_MASTER      (1 << 2)
#define PCI_COMMAND_MEM_SPACE       (1 << 1)
#define PCI_COMMAND_IO_SPACE        (1 << 0)

/* Macro to populate CONFIG_ADDR from bus, device, function, offset */

#define PCI_CONFIG_ADDR(bus, dev, fn, off) \
    (uint32_t)( \
           (1   << PCI_CONFIG_ADDRESS_ENABLE_BIT_SHIFT) | \
           (bus << PCI_CONFIG_ADDRESS_BUS_SHIFT) | \
           (dev << PCI_CONFIG_ADDRESS_DEVICE_SHIFT) | \
           (fn  << PCI_CONFIG_ADDRESS_FUNCTION_SHIFT) | \
           (off & PCI_CONFIG_ADDRESS_OFFSET_MASK))

#define PCI_BUS(conf) ((conf >> PCI_CONFIG_ADDRESS_BUS_SHIFT) & 0xFF)
#define PCI_DEV(conf) ((conf >> PCI_CONFIG_ADDRESS_DEVICE_SHIFT) & 0x7F)
#define PCI_FUN(conf) ((conf >> PCI_CONFIG_ADDRESS_FUNCTION_SHIFT) & 0x07)

#endif
