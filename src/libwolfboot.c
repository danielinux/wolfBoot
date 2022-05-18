/* libwolfboot.c
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
#include <inttypes.h>

#include "hal.h"
#include "wolfboot/wolfboot.h"
#include "image.h"

#define unit_dbg(...) do{}while(0)

#define TRAILER_SKIP 0

#define XMEMCPY memcpy
#define ENCRYPT_TMP_SECRET_OFFSET (WOLFBOOT_PARTITION_SIZE - (TRAILER_SKIP))

#ifndef NULL
#   define NULL (void *)0
#endif

static const uint32_t wolfboot_magic_trail = WOLFBOOT_MAGIC_TRAIL;
/* Top addresses for FLAGS field
 *  - PART_BOOT_ENDFLAGS = top of flags for BOOT partition
 *  - PART_UPDATE_ENDFLAGS = top of flags for UPDATE_PARTITION
 */

#ifndef PART_BOOT_ENDFLAGS
#define PART_BOOT_ENDFLAGS   (WOLFBOOT_PARTITION_BOOT_ADDRESS + ENCRYPT_TMP_SECRET_OFFSET)
#endif
#define FLAGS_BOOT_EXT() PARTN_IS_EXT(PART_BOOT)

/* FLAGS are at the end of each partition */
#define PART_UPDATE_ENDFLAGS (WOLFBOOT_PARTITION_UPDATE_ADDRESS + ENCRYPT_TMP_SECRET_OFFSET)
#define FLAGS_UPDATE_EXT() PARTN_IS_EXT(PART_UPDATE)

#define hal_trailer_write(addr, val) hal_flash_write(addr, (void *)&val, 1)
#define hal_set_partition_magic(addr) hal_flash_write(addr, (void*)&wolfboot_magic_trail, sizeof(uint32_t));

/*!
    \ingroup flags

    \brief Get the Nth byte of the trailer in the given partition (counting backwards)
    \return a pointer to the Nth-last byte of the trailer
    \param part partition id (PART_BOOT or PART_UPDATE)
    \param at offset from the end of the trailer flags
*/
static uint8_t* RAMFUNCTION get_trailer_at(uint8_t part, uint32_t at)
{
    if (part == PART_BOOT)
        return (void *)(PART_BOOT_ENDFLAGS - (sizeof(uint32_t) + at));
    else if (part == PART_UPDATE) {
        return (void *)(PART_UPDATE_ENDFLAGS - (sizeof(uint32_t) + at));
    } else
        return NULL;
}

/*!
    \ingroup flags

    \brief Set the Nth byte of the trailer in the given partition (counting backwards) to the given value
    \param part partition id (PART_BOOT or PART_UPDATE)
    \param at offset from the end of the trailer flags
    \param val new value for the byte at the given position
*/
static void RAMFUNCTION set_trailer_at(uint8_t part, uint32_t at, uint8_t val)
{
    if (part == PART_BOOT) {
        hal_trailer_write(PART_BOOT_ENDFLAGS - (sizeof(uint32_t) + at), val);
    }
    else if (part == PART_UPDATE) {
        hal_trailer_write(PART_UPDATE_ENDFLAGS - (sizeof(uint32_t) + at), val);
    }
}

/*!
    \ingroup flags

    \brief Set the magic sequence "BOOT" at the end of the partition, marking the validity 
           of the trailer flags.
    \param part partition id (PART_BOOT or PART_UPDATE)
*/
static void RAMFUNCTION set_partition_magic(uint8_t part)
{
    if (part == PART_BOOT) {
        hal_set_partition_magic(PART_BOOT_ENDFLAGS - sizeof(uint32_t));
    }
    else if (part == PART_UPDATE) {
        hal_set_partition_magic(PART_UPDATE_ENDFLAGS - sizeof(uint32_t));
    }
}

/*!
    \ingroup flags

    \brief Get the address where the magic sequence "BOOT" is expected,at the end of the partition, marking the validity 
           of the trailer flags.
    \return uint32_t pointer to the location where the magic sequence "BOOT" is expected
    \param part partition id (PART_BOOT or PART_UPDATE)
*/
static uint32_t* RAMFUNCTION get_partition_magic(uint8_t part)
{
    return (uint32_t *)get_trailer_at(part, 0);
}

/*!
    \ingroup flags

    \brief Get the update state of the partition.
    \return a pointer to the byte containing the partition state.
        Allowed values for this 1-byte field are IMG_STATE_NEW, IMG_STATE_TESTING, IMG_STATE_UPDATING, IMG_STATE_SUCCESS.
    \param part partition id (PART_BOOT or PART_UPDATE)
*/
static uint8_t* RAMFUNCTION get_partition_state(uint8_t part)
{
    return (uint8_t *)get_trailer_at(part, 1);
}

/*!
    \ingroup flags

    \brief Set the update state of the partition.
    \param part partition id (PART_BOOT or PART_UPDATE)
    \param val new value for the partition state flag.
        Allowed values for this 1-byte field are IMG_STATE_NEW, IMG_STATE_TESTING, IMG_STATE_UPDATING, IMG_STATE_SUCCESS.
*/
static void RAMFUNCTION set_partition_state(uint8_t part, uint8_t val)
{
    set_trailer_at(part, 1, val);
}


/*!
    \ingroup flags

    \brief Set the update state of the sector in the UPDATE partition.
    \param pos sector number
    \param val new value for the sector state flag.
        Allowed values for this 1-byte field are SECT_FLAG_NEW, SECT_FLAG_BACKUP, SECT_FLAG_SWAPPING, SECT_FLAG_UPDATED.
*/
static void RAMFUNCTION set_update_sector_flags(uint32_t pos, uint8_t val)
{
    set_trailer_at(PART_UPDATE, 2 + pos, val);
}

/*!
    \ingroup flags

    \brief Get the update state of the sector in the UPDATE partition.
    \return stored value for the sector state flag.
        Allowed values for this 1-byte field are SECT_FLAG_NEW, SECT_FLAG_BACKUP, SECT_FLAG_SWAPPING, SECT_FLAG_UPDATED.
    \param pos sector number
*/
static uint8_t* RAMFUNCTION get_update_sector_flags(uint32_t pos)
{
    return (uint8_t *)get_trailer_at(PART_UPDATE, 2 + pos);
}

/*!
    \ingroup flags

    \brief Set the update state of the partition via set_partition_state(), but first ensure that there is a magic sequence and 
           the state must be rewritten, to prevent unnecessary writes.
    \param part partition id (PART_BOOT or PART_UPDATE)
    \param newst new value for the partition state flag.
        Allowed values for this 1-byte field are IMG_STATE_NEW, IMG_STATE_TESTING, IMG_STATE_UPDATING, IMG_STATE_SUCCESS.
*/
int RAMFUNCTION wolfBoot_set_partition_state(uint8_t part, uint8_t newst)
{
    uint32_t *magic;
    uint8_t *state;
    magic = get_partition_magic(part);
    if (*magic != WOLFBOOT_MAGIC_TRAIL)
        set_partition_magic(part);
    state = get_partition_state(part);
    if (*state != newst)
        set_partition_state(part, newst);
    return 0;
}

/*!
    \ingroup flags

    \brief Set the update state of the given sector in the UPDATE partition, via set_update_sector_flags(),
            but first ensure that there is a magic sequence and 
            the state must be rewritten, to prevent unnecessary writes.
    \return 0 to indicate success
    \param sector sector number
    \param newflag new value for the sector state flag.
        Allowed values for this 1-byte field are SECT_FLAG_NEW, SECT_FLAG_BACKUP, SECT_FLAG_SWAPPING, SECT_FLAG_UPDATED.
*/
int RAMFUNCTION wolfBoot_set_update_sector_flag(uint16_t sector, uint8_t newflag)
{
    uint32_t *magic;
    uint8_t *flags;
    uint8_t fl_value;
    uint8_t pos = sector >> 1;

    magic = get_partition_magic(PART_UPDATE);
    if (*magic != wolfboot_magic_trail)
        set_partition_magic(PART_UPDATE);

    flags = get_update_sector_flags(pos);
    if (sector == (pos << 1))
        fl_value = (*flags & 0xF0) | (newflag & 0x0F);
    else
        fl_value = ((newflag & 0x0F) << 4) | (*flags & 0x0F);
    if (fl_value != *flags)
        set_update_sector_flags(pos, fl_value);
    return 0;
}


/*!
    \ingroup flags

    \brief Validate the partition magic sequence, then return the update state of the partition via get_partition_state
    \return 0 on success, and the state is stored in st, -1 on failure (missing magic sequence)
    \param part partition id (PART_UPDATE or PART_BOOT)
    \param st pointer to 1-byte uint8_t variable, populated with the state upon success
*/
int RAMFUNCTION wolfBoot_get_partition_state(uint8_t part, uint8_t *st)
{
    uint32_t *magic;
    uint8_t *state;
    magic = get_partition_magic(part);
    if (*magic != WOLFBOOT_MAGIC_TRAIL)
        return -1;
    state = get_partition_state(part);
    *st = *state;
    return 0;
}

/*!
    \ingroup flags

    \brief Validate the UPDATE partition magic sequence, then return the update state of the sector via get_update_sector_flags.
    \return 0 on success, and the state is stored in flag, -1 on failure (missing magic sequence)
    \param sector sector number
    \param flag pointer to 1-byte uint8_t variable, populated with the state upon success
*/
int wolfBoot_get_update_sector_flag(uint16_t sector, uint8_t *flag)
{
    uint32_t *magic;
    uint8_t *flags;
    uint8_t pos = sector >> 1;
    magic = get_partition_magic(PART_UPDATE);
    if (*magic != WOLFBOOT_MAGIC_TRAIL)
        return -1;
    flags = get_update_sector_flags(pos);
    if (sector == (pos << 1))
        *flag = *flags & 0x0F;
    else
        *flag = (*flags & 0xF0) >> 4;
    return 0;
}

/*!
    \ingroup libwolfboot

    \brief Called by the application to tell the bootloader that a new
           update candidate is available in the update partition
*/
void RAMFUNCTION wolfBoot_update_trigger(void)
{
    uint8_t st = IMG_STATE_UPDATING;
    if (FLAGS_UPDATE_EXT())
    {
        ext_flash_unlock();
        wolfBoot_set_partition_state(PART_UPDATE, st);
        ext_flash_lock();
    } else {
        hal_flash_unlock();
        wolfBoot_set_partition_state(PART_UPDATE, st);
        hal_flash_lock();
    }
}

/*!
    \ingroup libwolfboot

    \brief Called by the application to tell the bootloader that the
            boot has completed successfully. When called for the first time
            on a new image, this sets the IMG_STATE_SUCCESS flag to the BOOT partition
            trailer.
*/
void RAMFUNCTION wolfBoot_success(void)
{
    uint8_t st = IMG_STATE_SUCCESS;
    if (FLAGS_BOOT_EXT())
    {
        ext_flash_unlock();
        wolfBoot_set_partition_state(PART_BOOT, st);
        ext_flash_lock();
    } else {
        hal_flash_unlock();
        wolfBoot_set_partition_state(PART_BOOT, st);
        hal_flash_lock();
    }
}

/*!
    \ingroup manifestParser

    \brief find a specific header in the manifest. Return a pointer to the beginning
           of the header in *ptr, and the length as return value.
    \return 0 if the header is not found, the length of the header otherwise
    \param haystack pointer to the beginning of the headers in the manifest
    \param type the type of header to be searched (e.g. HDR_TIMESTAMP).
    \param ptr pointer to a uint8_t pointer that will be directed to the start of the header field when found
*/
uint16_t wolfBoot_find_header(uint8_t *haystack, uint16_t type, uint8_t **ptr)
{
    uint8_t *p = haystack;
    uint16_t len;
    const volatile uint8_t *max_p = (haystack - IMAGE_HEADER_OFFSET) + IMAGE_HEADER_SIZE;
    *ptr = NULL;
    if (p > max_p) {
        unit_dbg("Illegal address (too high)\n");
        return 0;
    }
    while ((p + 4) < max_p) {
        if ((p[0] == 0) && (p[1] == 0)) {
            unit_dbg("Explicit end of options reached\n");
            break;
        }
        if (*p == HDR_PADDING) {
            /* Padding byte (skip one position) */
            p++;
            continue;
        }
        /* Sanity check to prevent dereferencing unaligned half-words */
        if ((((unsigned long)p) & 0x01) != 0) {
            p++;
            continue;
        }
        len = p[2] | (p[3] << 8);
        if ((4 + len) > (uint16_t)(IMAGE_HEADER_SIZE - IMAGE_HEADER_OFFSET)) {
            unit_dbg("This field is too large (bigger than the space available in the current header)\n");
            break;
        }
        if (p + 4 + len > max_p) {
            unit_dbg("This field is too large and would overflow the image header\n");
            break;
        }
        if ((p[0] | (p[1] << 8)) == type) {
            *ptr = (p + 4);
            return len;
        }
        p += 4 + len;
    }
    return 0;
}

/*!
    \ingroup manifestParser

    \brief Get the image version stored in the manifest.
    \return The version value, stored in the manifest, or 0 to indicate an error
    \param blob the firmware image
*/
uint32_t wolfBoot_get_blob_version(uint8_t *blob)
{
    uint32_t *version_field = NULL;
    uint32_t *magic = NULL;
    magic = (uint32_t *)blob;
    if (*magic != WOLFBOOT_MAGIC)
        return 0;
    if (wolfBoot_find_header(blob + IMAGE_HEADER_OFFSET, HDR_VERSION, (void *)&version_field) == 0)
        return 0;
    if (version_field)
        return *version_field;
    return 0;
}

/*!
    \ingroup manifestParser

    \brief Get the image version of the current image in a given partition.
    \return The version value, stored in the manifest, or 0 to indicate an error
    \param part the partition id (PART_BOOT or PART_UPDATE)
*/
uint32_t wolfBoot_get_image_version(uint8_t part)
{
    uint8_t *image = (uint8_t *)0x00000000;
    if(part == PART_UPDATE) {
        if (PARTN_IS_EXT(PART_UPDATE))
        {
        } else {
            image = (uint8_t *)WOLFBOOT_PARTITION_UPDATE_ADDRESS;
        }
    } else if (part == PART_BOOT) {
        if (PARTN_IS_EXT(PART_BOOT)) {
        } else {
            image = (uint8_t *)WOLFBOOT_PARTITION_BOOT_ADDRESS;
        }
    }
    /* Don't check image against NULL to allow using address 0x00000000 */
    return wolfBoot_get_blob_version(image);
}

/*!
    \ingroup manifestParser

    \brief Get the image type of the current image in a given partition.
    \return value of the type field stored in the manifest, or 0 to indicate an error
    \param part the partition id (PART_BOOT or PART_UPDATE)
*/
uint16_t wolfBoot_get_image_type(uint8_t part)
{
    uint16_t *type_field = NULL;
    uint8_t *image = NULL;
    uint32_t *magic = NULL;
    if(part == PART_UPDATE) {
        if (PARTN_IS_EXT(PART_UPDATE))
        {
        } else {
            image = (uint8_t *)WOLFBOOT_PARTITION_UPDATE_ADDRESS;
        }
    } else if (part == PART_BOOT) {
        if (PARTN_IS_EXT(PART_BOOT)) {
        } else {
            image = (uint8_t *)WOLFBOOT_PARTITION_BOOT_ADDRESS;
        }
    }

    if (image) {
        magic = (uint32_t *)image;
        if (*magic != WOLFBOOT_MAGIC)
            return 0;
        if (wolfBoot_find_header(image + IMAGE_HEADER_OFFSET, HDR_IMG_TYPE, (void *)&type_field) == 0)
            return 0;
        if (type_field)
            return *type_field;
    }

    return 0;
}

