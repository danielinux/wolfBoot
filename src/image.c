/* image.c
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

#include "loader.h"
#include "image.h"
#include "hal.h"
#include "spi_drv.h"
#include <stddef.h>

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFBOOT_SIGN_ECC256) || defined(WOLFBOOT_SIGN_ECC384) \
    || defined(WOLFBOOT_SIGN_ECC521)

#include <wolfssl/wolfcrypt/ecc.h>

#ifdef WOLFBOOT_SIGN_ECC256
    #define ECC_KEY_SIZE  32
    #define ECC_KEY_TYPE ECC_SECP256R1
#endif
#ifdef WOLFBOOT_SIGN_ECC384
    #define ECC_KEY_SIZE  48
    #define ECC_KEY_TYPE ECC_SECP384R1
#endif
#ifdef WOLFBOOT_SIGN_ECC521
    #define ECC_KEY_SIZE  66
    #define ECC_KEY_TYPE ECC_SECP521R1
#endif

/*!
    \ingroup image

    \brief Verify signature for a firmware image mapped in memory, by verifying the
        signature in the manifest header. If the verification is successful, VERIFY_FN macro
       will set the signature_ok flag in the structure pointed by img. 
    \param img the structure describing the firmware image to be verified
    \param sig a buffer containing the signature, in raw R, S format, to be verified using
        the ECC algorithm selected at compile time.
    \sa wolfBoot_image_confirm_signature_ok
    \sa wolfBoot_verify_integrity
    \sa wolfBoot_verify_authenticity
*/
static void wolfBoot_verify_signature(struct wolfBoot_image *img, uint8_t *sig)
{
    int ret, verify_res = 0;
    /* wolfCrypt software ECC verify */
    mp_int r, s;
    ecc_key ecc;

    ret = wc_ecc_init(&ecc);
    if (ret < 0) {
        /* Failed to initialize key */
        return;
    }

    /* Import public key */
    ret = wc_ecc_import_unsigned(&ecc, (byte*)KEY_BUFFER,
        (byte*)(KEY_BUFFER + ECC_KEY_SIZE), NULL, ECC_KEY_TYPE);
    if ((ret < 0) || ecc.type != ECC_PUBLICKEY) {
        /* Failed to import ecc key */
        return;
    }

    /* Import signature into r,s */
    mp_init(&r);
    mp_init(&s);
    mp_read_unsigned_bin(&r, sig, ECC_KEY_SIZE);
    mp_read_unsigned_bin(&s, sig + ECC_KEY_SIZE, ECC_KEY_SIZE);
    VERIFY_FN(img, &verify_res, wc_ecc_verify_hash_ex, &r, &s, img->sha_hash,
            WOLFBOOT_SHA_DIGEST_SIZE, &verify_res, &ecc);
}
#endif /* WOLFBOOT_SIGN_ECC256 */


/*!
    \ingroup image

    \brief Look up a header by its tag in the manifest of a firmware image.
    \return The length of the data field for the header, if the header was found.
    \param img pointer to the structure describing a firmware image
    \param type parameter tag/type to search in the header
    \param ptr pointer to a pointer, used as return value to store the address of the match
*/
static uint16_t get_header(struct wolfBoot_image *img, uint16_t type, uint8_t **ptr)
{
    return wolfBoot_find_header(img->hdr + IMAGE_HEADER_OFFSET, type, ptr);
}

/* Keep a static buffer to store image digest */
static uint8_t digest[WOLFBOOT_SHA_DIGEST_SIZE];


/*!
    \ingroup image

    \brief Retrieve a pointer to a block of the firmware image, at a given offset.
    \return A pointer to the beginning of the requested block.
    \param img pointer to the structure describing a firmware image
    \param offset offset of the requested block from the beginning of the image
*/
static uint8_t *get_sha_block(struct wolfBoot_image *img, uint32_t offset)
{
    if (offset > img->fw_size)
        return NULL;
    return (uint8_t *)(img->fw_base + offset);
}

#   define fetch_hdr_cpy(i) ((uint8_t *)0)
/*!
    \ingroup image

    \brief Return the header of the firmware image if directly accessible
    (memory mapped), or preload an external image header into a local cache buffer.
    \return The pointer to the header (direct or cached).
    \param img pointer to the structure describing a firmware image
*/
static uint8_t *get_img_hdr(struct wolfBoot_image *img)
{
    if (PART_IS_EXT(img))
        return fetch_hdr_cpy(img);
    else
        return (uint8_t *)(img->hdr);
}

#if defined(WOLFBOOT_HASH_SHA256)
#include <wolfssl/wolfcrypt/sha256.h>
/*!
    \ingroup image

    \brief Calculate the digest of a stored firmware image, including the fields
        in the manifest that are part of the verification.
    \return 0 on success, -1 in case of errors parsing the image.
    \param img pointer to the structure describing a firmware image
    \param hash pointer to a buffer that will contain the hash after the operation if 0 is returned
*/
static int image_sha256(struct wolfBoot_image *img, uint8_t *hash)
{
    uint8_t *stored_sha, *end_sha;
    uint16_t stored_sha_len;
    uint8_t *p;
    int blksz;
    uint32_t position = 0;
    wc_Sha256 sha256_ctx;
    if (!img)
        return -1;
    p = get_img_hdr(img);
    stored_sha_len = get_header(img, HDR_SHA256, &stored_sha);
    if (stored_sha_len != WOLFBOOT_SHA_DIGEST_SIZE)
        return -1;
    wc_InitSha256(&sha256_ctx);
    end_sha = stored_sha - (2 * sizeof(uint16_t)); /* Subtract 2 Type + 2 Len */
    while (p < end_sha) {
        blksz = WOLFBOOT_SHA_BLOCK_SIZE;
        if (end_sha - p < blksz)
            blksz = end_sha - p;
        wc_Sha256Update(&sha256_ctx, p, blksz);
        p += blksz;
    }
    do {
        p = get_sha_block(img, position);
        if (p == NULL)
            break;
        blksz = WOLFBOOT_SHA_BLOCK_SIZE;
        if (position + blksz > img->fw_size)
            blksz = img->fw_size - position;
        wc_Sha256Update(&sha256_ctx, p, blksz);
        position += blksz;
    } while(position < img->fw_size);

    wc_Sha256Final(&sha256_ctx, hash);
    return 0;
}

/*!
    \ingroup image

    \brief Calculate the digest of the default stored public key in KEY_BUFFER.
    \return 0 on success, -1 in case of errors parsing the key.
    \param hash pointer to a buffer that will contain the hash after the operation if 0 is returned
*/
static void key_sha256(uint8_t *hash)
{
    int blksz;
    unsigned int i = 0;
    wc_Sha256 sha256_ctx;
    wc_InitSha256(&sha256_ctx);
    while(i < KEY_LEN)
    {
        blksz = WOLFBOOT_SHA_BLOCK_SIZE;
        if ((i + blksz) > KEY_LEN)
            blksz = KEY_LEN - i;
        wc_Sha256Update(&sha256_ctx, (KEY_BUFFER + i), blksz);
        i += blksz;
    }
    wc_Sha256Final(&sha256_ctx, hash);
}

#endif /* SHA2-256 */


/*!
    \ingroup image

    \brief Return the size of the firmware image after reading it from the beginning of the manifest.
    \return The size stored in the manifest header
    \param img pointer to the structure describing a firmware image
*/
uint32_t wolfBoot_image_size(uint8_t *image)
{
    uint32_t *size = (uint32_t *)(image + sizeof (uint32_t));
    return *size;
}

/*!
    \ingroup image

    \brief Associate the firmware in the partition part to the object pointed by *img. Check
    that the image contained in the partition contains a valid header, then populate the fields
    in the structure.
    \return 0 on success, -1 if the manifest could not be parsed, or the size is invalid.
    \param img pointer to the structure describing a firmware image
    \param part id of the partition (PART_BOOT, PART_UPDATE)
*/
int wolfBoot_open_image(struct wolfBoot_image *img, uint8_t part)
{
    uint32_t *magic;
    uint32_t *size;
    uint8_t *image;
    if (!img)
        return -1;
    memset(img, 0, sizeof(struct wolfBoot_image));
    img->part = part;
    if (part == PART_SWAP) {
        img->hdr_ok = 1;
        img->hdr = (void*)WOLFBOOT_PARTITION_SWAP_ADDRESS;
        img->fw_base = img->hdr;
        img->fw_size = WOLFBOOT_SECTOR_SIZE;
        return 0;
    }
    if (part == PART_BOOT) {
        img->hdr = (void*)WOLFBOOT_PARTITION_BOOT_ADDRESS;
    } else if (part == PART_UPDATE) {
        img->hdr = (void*)WOLFBOOT_PARTITION_UPDATE_ADDRESS;
    } else
        return -1;

    /* fetch header address
     * (or copy from external device to a local buffer via fetch_hdr_cpy)
     */
    if (PART_IS_EXT(img))
        image = fetch_hdr_cpy(img);
    else
        image = (uint8_t *)img->hdr;

    magic = (uint32_t *)(image);
    if (*magic != WOLFBOOT_MAGIC)
        return -1;
    img->fw_size = wolfBoot_image_size(image);
    if (img->fw_size > (WOLFBOOT_PARTITION_SIZE - IMAGE_HEADER_SIZE)) {
        img->fw_size = 0;
        return -1;
    }
    img->hdr_ok = 1;
    img->fw_base = img->hdr + IMAGE_HEADER_SIZE;
    img->trailer = img->hdr + WOLFBOOT_PARTITION_SIZE;
    return 0;
}

/*!
    \ingroup image

    \brief Verify that the image stored in the manifest corresponds to the hash calculated on
           the firmware image.
    \return 0 on success, -1 if the hash is invalid or does not match.
    \param img pointer to the structure describing a firmware image
*/
int wolfBoot_verify_integrity(struct wolfBoot_image *img)
{
    uint8_t *stored_sha;
    uint16_t stored_sha_len;
    stored_sha_len = get_header(img, WOLFBOOT_SHA_HDR, &stored_sha);
    if (stored_sha_len != WOLFBOOT_SHA_DIGEST_SIZE)
        return -1;
    if (image_hash(img, digest) != 0)
        return -1;
    if (memcmp(digest, stored_sha, stored_sha_len) != 0)
        return -1;
    img->sha_ok = 1;
    img->sha_hash = stored_sha;
    return 0;
}

/*!
    \ingroup image

    \brief Verify that the signature stored in the manifest can be authenticated.
    \return 0 on success, -1 on error, -2 if the signature is not valid.
    \param img pointer to the structure describing a firmware image to be validated
*/
int wolfBoot_verify_authenticity(struct wolfBoot_image *img)
{
    int ret;
    uint8_t *stored_signature;
    uint16_t stored_signature_size;
    uint8_t *pubkey_hint;
    uint16_t pubkey_hint_size;
    uint8_t *image_type_buf;
    uint16_t image_type;
    uint16_t image_type_size;

    stored_signature_size = get_header(img, HDR_SIGNATURE, &stored_signature);
    if (stored_signature_size != IMAGE_SIGNATURE_SIZE)
       return -1;
    pubkey_hint_size = get_header(img, HDR_PUBKEY, &pubkey_hint);
    if (pubkey_hint_size == WOLFBOOT_SHA_DIGEST_SIZE) {
        key_hash(digest);
        if (memcmp(digest, pubkey_hint, WOLFBOOT_SHA_DIGEST_SIZE) != 0)
            return -1;
    }
    image_type_size = get_header(img, HDR_IMG_TYPE, &image_type_buf);
    if (image_type_size != sizeof(uint16_t))
            return -1;
    image_type = (uint16_t)(image_type_buf[0] + (image_type_buf[1] << 8));
    if ((image_type & 0xFF00) != HDR_IMG_TYPE_AUTH)
        return -1;
    if (img->sha_hash == NULL) {
        if (image_hash(img, digest) != 0)
            return -1;
        img->sha_hash = digest;
    }
    /* wolfBoot_verify_signature() does not return the result directly.
     * A call to wolfBoot_image_confirm_signature_ok() is required in order to
     * confirm that the signature verification is OK.
     *
     * only a call to wolfBoot_image_confirm_signature_ok() sets
     * img->signature_ok to 1.
     *
     */
    wolfBoot_verify_signature(img, stored_signature);
    if (img->signature_ok == 1)
        return 0;
    return -2;
}

