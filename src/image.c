/* image.c
 *
 * Copyright (C) 2020 wolfSSL Inc.
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

#ifndef WOLFTPM2_NO_WOLFCRYPT
#include <wolfssl/wolfcrypt/settings.h>
#include <stddef.h>
#include <string.h>
#endif

#ifdef WOLFBOOT_HASH_SHA256
#include <wolfssl/wolfcrypt/sha256.h>
#endif

#ifdef WOLFBOOT_HASH_SHA3_384
#include <wolfssl/wolfcrypt/sha3.h>
#endif

#ifdef WOLFBOOT_SIGN_ED25519
#include <wolfssl/wolfcrypt/ed25519.h>
#endif

#ifdef WOLFBOOT_SIGN_ECC256
#include <wolfssl/wolfcrypt/ecc.h>
#define ECC_KEY_SIZE  32
#define ECC_SIG_SIZE  64
#endif

#if defined(WOLFBOOT_SIGN_RSA2048) || defined (WOLFBOOT_SIGN_RSA4096)
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#endif

#ifndef WOLFTPM2_NO_WOLFCRYPT /* wolfBoot with wolfCrypt (no TPM) */
static int wolfBoot_verify_signature(uint8_t *hash, uint8_t *sig);

#ifndef ARCH_ARM
#   define NO_GLITCH_PROTECTION
#endif

#ifndef NO_GLITCH_PROTECTION
static void panic(void)
{
    while(1) {
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
    }

}

#define CANARY_VAL 0xBADDCAFEUL
static volatile uint32_t __attribute__((unused)) staticmem_can_0 = 0xBADDCAFE;
static int verification_result = 0;
static uint32_t pcres = 0;
static int dwt_count = 0;
static volatile uint32_t __attribute__((unused)) staticmem_can_1 = 0xBADDCAFE;

#define DWT_BASE (0xE0001000)
#define DWT_CTRL        *((volatile uint32_t *)(DWT_BASE))
#define DWT_PCSR        *((volatile uint32_t *)(DWT_BASE + 0x1C))
#define DWT_COMP(x)     *((volatile uint32_t *)(DWT_BASE + 0x20 + (x << 4)))
#define DWT_MASK(x)     *((volatile uint32_t *)(DWT_BASE + 0x24 + (x << 4)))
#define DWT_FUNCTION(x) *((volatile uint32_t *)(DWT_BASE + 0x28 + (x <<4)))
#define SYS_DEMCR       *((volatile uint32_t *)(0xE000EDFC))
#define SYS_DHCSR       *((volatile uint32_t *)(0xE000EDF0))

#define DWT_CTRL_EXCTRCENA (1 << 16)
#define DWT_CTRL_NOTRCPKT  (1 << 27)
#define ITM_TCR   *((volatile uint32_t *)(0xe0000e80))
#define ITM_TPR   *((volatile uint32_t *)(0xe0000e40))
#define ITM_TER   *((volatile uint32_t *)(0xe0000e00))
#define ITM_LAR   *((volatile uint32_t *)(0xe0000fb0))
#define ITM_ACCESS (0xC5ACCE55)
#define ITM_TXENA (1 << 3)
#define ITM_ITMENA (1 << 0)

#define NVIC_ISER_BASE *((volatile uint32_t *)(0xE000E100))
#define NVIC_ICER_BASE *((volatile uint32_t *)(0xE000E180))

#define DWT_DATAVMATCH (1 << 8)
#define DWT_DATASIZE_WORD (1 << 11)
#define DWT_WATCHFN_WO      (6 << 0)
#define DWT_MATCHED      (1 << 24)
#define DEMCR_TRCENA     (1 << 24)
#define DEMCR_MON_PEND   (1 << 17)
#define DEMCR_MON_EN     (1 << 16)
#define DEMCR_VC_CORERESET (1 << 0)
#define CHECK(X) if((X) != CANARY_VAL) panic()

#define DBG_DHCSR_KEY ((0xA0 << 24) | (0x5F << 16))
#define DBG_DHCSR_HALT (1 << 1)
#define DBG_DHCSR_STEP (1 << 2)
#define DBG_DEMCR_MON_STEP (1 << 18)
#define DBG_DEMCR_MON_PEND (1 << 17)
#define DBG_DEMCR_MON_EN (1 << 16)

#define FPB_BASE            (0xE0002000)
#define FPB_CTRL			*((volatile uint32_t *)(FPB_BASE + 0))
#define FPB_REMAP			*((volatile uint32_t *)(FPB_BASE + 4))
#define FPB_COMP0			*((volatile uint32_t *)(FPB_BASE + 8))
#define FPB_LSR				*((volatile uint32_t *)(FPB_BASE + 0xFB4))
#define FPB_LAR				*((volatile uint32_t *)(FPB_BASE + 0xFB0))
#define FPB_CTRL_NUM_CODE2_MASK		(0x7 << 12)
#define FPB_CTRL_NUM_LIT_MASK		(0xf << 8)
#define FPB_CTRL_NUM_CODE1_MASK		(0xf << 4)
#define FPB_CTRL_KEY			(1 << 1)
#define FPB_CTRL_ENABLE			(1 << 0)
#define FPB_REPLACE_LO (1 << 30)
#define FPB_REPLACE_HI (2 << 30)
#define FPB_REPLACE_BOTH (3 << 30)
#define FPB_COMP_ENABLE			(1 << 0)

#define FPB_NUM_CODE2_OFF   12
#define FPB_NUM_LIT_MASK_OFF 8
#define FPB_NUM_CODE1_OFF    4

#define PC_SETRESULT (0x0a0000) /* TODO */

void isr_dwt(void)
{
   volatile uint32_t pc = DWT_PCSR;
   uint32_t fn = DWT_FUNCTION(0);
   if ((verification_result != 0) && (pc != PC_SETRESULT))
        panic();
   pcres = pc; 
   SYS_DEMCR &= ~DEMCR_MON_PEND;
   dwt_count += (fn & DWT_MATCHED) >> 24;
}

#if 0
void isr_dwt(void)
{
    SYS_DEMCR &= ~DEMCR_MON_PEND;
    dwt_count++;
}
#endif


int wolfBoot_protect_verify_signature(uint8_t *hash, uint8_t *sig)
{
    unsigned int canary_0 = CANARY_VAL;
    int ret;
    unsigned int canary_1 = CANARY_VAL;
    void *bpoint = wc_ed25519_verify_msg;
    verification_result = 0;
    pcres = 0;
    dwt_count = 0;
    /* Enable Debug Monitor Exception */
    SYS_DEMCR = DEMCR_TRCENA | DBG_DEMCR_MON_EN | DEMCR_VC_CORERESET;

    /* Breakpoint */
#if 0
    if (FPB_CTRL == 0x0) {
        return -1;
    }
    if (FPB_COMP0 == 0x0) {
        return -1;
    }
    FPB_CTRL = FPB_CTRL_ENABLE | FPB_CTRL_KEY | (1 << FPB_NUM_CODE2_OFF) | (2 << FPB_NUM_LIT_MASK_OFF);
    if ((uint32_t)bpoint & 0x02)
        FPB_COMP0 = FPB_COMP_ENABLE | (((uint32_t)bpoint) & (0x1FFFFFFC)) | FPB_REPLACE_HI;
    else
        FPB_COMP0 = FPB_COMP_ENABLE | (((uint32_t)bpoint) & (0x1FFFFFFC)) | FPB_REPLACE_LO;
#endif
    DWT_COMP(0) = (uint32_t)&verification_result;
    DWT_FUNCTION(0) = DWT_WATCHFN_WO;
    DWT_MASK(0) = 2;
    ITM_LAR = ITM_ACCESS;
    ITM_TCR = 0x0001000d;
    ITM_TER = 0xFFFFFFFF;
    ITM_TPR = 0xFFFFFFFF;


    NVIC_ISER_BASE |= 1;
    ret = wolfBoot_verify_signature(hash, sig);
    /*
    if (pcres!=PC_SETRESULT) {
        panic();
    }
    */
    if (dwt_count < 1)
        panic();
    CHECK(canary_0);
    CHECK(canary_1);
    CHECK(staticmem_can_0);
    CHECK(staticmem_can_1);
    SYS_DEMCR = 0;
    return verification_result?0:-1;
}
#else
#define wolfBoot_protect_verify_signature(h,s) wolfBoot_verify_signature(h,s)
#endif /* Glitch protection */


#ifdef WOLFBOOT_SIGN_ED25519
static int wolfBoot_verify_signature(uint8_t *hash, uint8_t *sig)
{
    int ret;
    ed25519_key ed;
    ret = wc_ed25519_init(&ed);
    if (ret < 0) {
        /* Failed to initialize key */
        return -1;
    }
    ret = wc_ed25519_import_public(KEY_BUFFER, KEY_LEN, &ed);
    if (ret < 0) {
        /* Failed to import ed25519 key */
        return -1;
    }
    ret = wc_ed25519_verify_msg(sig, IMAGE_SIGNATURE_SIZE, hash, WOLFBOOT_SHA_DIGEST_SIZE, &verification_result, &ed);
    if ((ret < 0) || (verification_result == 0)) {
        return -1;
    }
    return 0;
}
#endif /* WOLFBOOT_SIGN_ED25519 */

#ifdef WOLFBOOT_SIGN_ECC256
static int wolfBoot_verify_signature(uint8_t *hash, uint8_t *sig)
{
    int ret;
    mp_int r, s;
    ecc_key ecc;
    ret = wc_ecc_init(&ecc);
    if (ret < 0) {
        /* Failed to initialize key */
        return -1;
    }

    /* Import public key */
    ret = wc_ecc_import_unsigned(&ecc, (byte*)KEY_BUFFER, (byte*)(KEY_BUFFER + 32), NULL, ECC_SECP256R1);
    if ((ret < 0) || ecc.type != ECC_PUBLICKEY) {
        /* Failed to import ecc key */
        return -1;
    }

    /* Import signature into r,s */
    mp_init(&r);
    mp_init(&s);
    mp_read_unsigned_bin(&r, sig, ECC_KEY_SIZE);
    mp_read_unsigned_bin(&s, sig + ECC_KEY_SIZE, ECC_KEY_SIZE);
    ret = wc_ecc_verify_hash_ex(&r, &s, hash, WOLFBOOT_SHA_DIGEST_SIZE, &verification_result, &ecc);
    if ((ret < 0) || (verification_result == 0)) {
        return -1;
    }
    return 0;
}
#endif /* WOLFBOOT_SIGN_ECC256 */

#if defined(WOLFBOOT_SIGN_RSA2048) || defined (WOLFBOOT_SIGN_RSA4096)
static int wolfBoot_verify_signature(uint8_t *hash, uint8_t *sig)
{
    int ret;
    struct RsaKey rsa;
    uint8_t digest_out[IMAGE_SIGNATURE_SIZE];
    word32 in_out = 0;

    ret = wc_InitRsaKey(&rsa, NULL);
    if (ret < 0) {
        /* Failed to initialize key */
        return -1;
    }
    /* Import public key */
    ret = wc_RsaPublicKeyDecode((byte*)KEY_BUFFER, &in_out, &rsa, KEY_LEN);
    if (ret < 0) {
        /* Failed to import rsa key */
        return -1;
    }
    ret = wc_RsaSSL_Verify(sig, IMAGE_SIGNATURE_SIZE, digest_out, IMAGE_SIGNATURE_SIZE, &rsa);
    if (ret == WOLFBOOT_SHA_DIGEST_SIZE) {
        if (memcmp(digest_out, hash, ret) == 0)
            return 0;
    }
    return -1;
}
#endif /* WOLFBOOT_SIGN_RSA2048 */

#else /* TPM2 */
#include <stdlib.h>
#include <string.h>
#include "wolftpm/tpm2.h"
#include "wolftpm/tpm2_wrap.h"
static WOLFTPM2_DEV wolftpm_dev;

#endif /* WOLFTPM2_NO_WOLFCRYPT */

static uint16_t get_header_ext(struct wolfBoot_image *img, uint16_t type, uint8_t **ptr);

static uint16_t get_header(struct wolfBoot_image *img, uint16_t type, uint8_t **ptr)
{
    if (PART_IS_EXT(img))
        return get_header_ext(img, type, ptr);
    else
        return wolfBoot_find_header(img->hdr + IMAGE_HEADER_OFFSET, type, ptr);
}

static uint8_t ext_hash_block[WOLFBOOT_SHA_BLOCK_SIZE];

static uint8_t *get_sha_block(struct wolfBoot_image *img, uint32_t offset)
{
    if (offset > img->fw_size)
        return NULL;
    if (PART_IS_EXT(img)) {
        ext_flash_read((uintptr_t)(img->fw_base) + offset, ext_hash_block, WOLFBOOT_SHA_BLOCK_SIZE);
        return ext_hash_block;
    } else
        return (uint8_t *)(img->fw_base + offset);
}

static uint8_t digest[WOLFBOOT_SHA_DIGEST_SIZE];

#ifdef EXT_FLASH

static uint8_t hdr_cpy[IMAGE_HEADER_SIZE];
static int hdr_cpy_done = 0;

static uint8_t *fetch_hdr_cpy(struct wolfBoot_image *img)
{
    if (!hdr_cpy_done) {
        ext_flash_read((uintptr_t)img->hdr, hdr_cpy, IMAGE_HEADER_SIZE);
        hdr_cpy_done = 1;
    }
    return hdr_cpy;
}

static uint16_t get_header_ext(struct wolfBoot_image *img, uint16_t type, uint8_t **ptr)
{
    return wolfBoot_find_header(fetch_hdr_cpy(img) + IMAGE_HEADER_OFFSET, type, ptr);
}

#else
#   define fetch_hdr_cpy(i) ((uint8_t *)0)
static uint16_t get_header_ext(struct wolfBoot_image *img, uint16_t type, uint8_t **ptr) { return 0; }
#endif

static uint8_t *get_img_hdr(struct wolfBoot_image *img)
{
    if (PART_IS_EXT(img))
        return fetch_hdr_cpy(img);
    else
        return (uint8_t *)(img->hdr);
}

#ifndef WOLFTPM2_NO_WOLFCRYPT

#if defined(WOLFBOOT_HASH_SHA256)
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
#endif /* SHA2 256 */
#if defined(WOLFBOOT_HASH_SHA3_384)
static int image_sha3_384(struct wolfBoot_image *img, uint8_t *hash)
{
    uint8_t *stored_sha, *end_sha;
    uint16_t stored_sha_len;
    uint8_t *p;
    int blksz;
    uint32_t position = 0;
    wc_Sha3 sha3_ctx;
    if (!img)
        return -1;
    p = get_img_hdr(img);
    stored_sha_len = get_header(img, HDR_SHA3_384, &stored_sha);
    if (stored_sha_len != WOLFBOOT_SHA_DIGEST_SIZE)
        return -1;
    wc_InitSha3_384(&sha3_ctx, NULL, INVALID_DEVID);
    end_sha = stored_sha - (2 * sizeof(uint16_t)); /* Subtract 2 Type + 2 Len */
    while (p < end_sha) {
        blksz = WOLFBOOT_SHA_BLOCK_SIZE;
        if (end_sha - p < blksz)
            blksz = end_sha - p;
        wc_Sha3_384_Update(&sha3_ctx, p, blksz);
        p += blksz;
    }
    do {
        p = get_sha_block(img, position);
        if (p == NULL)
            break;
        blksz = WOLFBOOT_SHA_BLOCK_SIZE;
        if (position + blksz > img->fw_size)
            blksz = img->fw_size - position;
        wc_Sha3_384_Update(&sha3_ctx, p, blksz);
        position += blksz;
    } while(position < img->fw_size);

    wc_Sha3_384_Final(&sha3_ctx, hash);
    return 0;
}

static void key_sha3_384(uint8_t *hash)
{
    int blksz;
    unsigned int i = 0;
    wc_Sha3 sha3_ctx;
    wc_InitSha3_384(&sha3_ctx, NULL, INVALID_DEVID);
    while(i < KEY_LEN)
    {
        blksz = WOLFBOOT_SHA_BLOCK_SIZE;
        if ((i + blksz) > KEY_LEN)
            blksz = KEY_LEN - i;
        wc_Sha3_384_Update(&sha3_ctx, (KEY_BUFFER + i), blksz);
        i += blksz;
    }
    wc_Sha3_384_Final(&sha3_ctx, hash);
}
#endif

#else /* WOLFTPM2_NO_WOLFCRYPT */

static int TPM2_IoCb(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
    word16 xferSz, void* userCtx)
{
    (void)userCtx;
    (void)ctx;
    word16 i;
    spi_cs_on(SPI_CS_TPM);
    memset(rxBuf, 0, xferSz);
    for (i = 0; i < xferSz; i++)
    {
        spi_write(txBuf[i]);
        rxBuf[i] = spi_read();
    }
    spi_cs_off(SPI_CS_TPM);
    /*
    printf("\r\nSPI TX: ");
    printbin(txBuf, xferSz);
    printf("SPI RX: ");
    printbin(rxBuf, xferSz);
    printf("\r\n");
    */
    return 0;
}

#define ECC_INT_SIZE 32
static int wolfBoot_verify_signature(uint8_t *hash, uint8_t *sig)
{
    int rc;
    int curve_id = TPM_ECC_NIST_P256;
    WOLFTPM2_KEY tpmKey;

    /* Load public key into TPM */
    rc = wolfTPM2_LoadEccPublicKey(&wolftpm_dev, &tpmKey, TPM_ECC_NIST_P256,
            KEY_BUFFER, ECC_INT_SIZE,
            KEY_BUFFER + ECC_INT_SIZE, ECC_INT_SIZE);
    if (rc < 0)
        return -1;
    rc = wolfTPM2_VerifyHash(&wolftpm_dev, &tpmKey, sig, 2 * ECC_INT_SIZE, hash, WOLFBOOT_SHA_DIGEST_SIZE);
    wolfTPM2_UnloadHandle(&wolftpm_dev, &tpmKey.handle);
    if (rc < 0)
        return -1;
    return 0;
}

int wolfBoot_tpm2_init(void)
{
    int rc;
    word32 idx;
    WOLFTPM2_CAPS caps;
    spi_init(0,0);

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&wolftpm_dev, TPM2_IoCb, NULL);
    if (rc != 0)  {
        return rc;
    }

    /* Get device capabilities + options */
    rc = wolfTPM2_GetCapabilities(&wolftpm_dev, &caps);
    if (rc != 0)  {
        return rc;
    }
    return 0;
}

static void key_sha256(uint8_t *hashBuf)
{
    int blksz, rc;
    unsigned int i = 0;
    const char gUsageAuth[]="wolfBoot TPM Usage Auth";
    uint32_t hashSz = WOLFBOOT_SHA_DIGEST_SIZE;
    WOLFTPM2_HASH hash;
    XMEMSET(&hash, 0, sizeof(hash));
    rc = wolfTPM2_HashStart(&wolftpm_dev, &hash, TPM_ALG_SHA256,
        (const byte*)gUsageAuth, sizeof(gUsageAuth)-1);
    if (rc != 0)
        return;
    while(i < KEY_LEN)
    {
        blksz = WOLFBOOT_SHA_BLOCK_SIZE;
        if ((i + blksz) > KEY_LEN)
            blksz = KEY_LEN - i;
        wolfTPM2_HashUpdate(&wolftpm_dev, &hash, KEY_BUFFER + i, blksz);
        i += blksz;
    }
    wolfTPM2_HashFinish(&wolftpm_dev, &hash, hashBuf, &hashSz);
}

static int image_sha256(struct wolfBoot_image *img, uint8_t *hashBuf)
{
    const char gUsageAuth[]="wolfBoot TPM Usage Auth";
    uint8_t *stored_sha, *end_sha;
    uint16_t stored_sha_len;
    uint8_t *p;
    int blksz;
    uint32_t position = 0;
    WOLFTPM2_HASH hash;
    uint32_t hashSz = WOLFBOOT_SHA_DIGEST_SIZE;
    int rc;
    if (!img)
        return -1;
    p = get_img_hdr(img);
    stored_sha_len = get_header(img, HDR_SHA256, &stored_sha);
    if (stored_sha_len != WOLFBOOT_SHA_DIGEST_SIZE)
        return -1;
    XMEMSET(&hash, 0, sizeof(hash));
    rc = wolfTPM2_HashStart(&wolftpm_dev, &hash, TPM_ALG_SHA256,
        (const byte*)gUsageAuth, sizeof(gUsageAuth)-1);
    if (rc != 0)
        return -1;
    end_sha = stored_sha - (2 * sizeof(uint16_t)); /* Subtract 2 Type + 2 Len */
    while (p < end_sha) {
        blksz = WOLFBOOT_SHA_BLOCK_SIZE;
        if (end_sha - p < blksz)
            blksz = end_sha - p;
        wolfTPM2_HashUpdate(&wolftpm_dev, &hash, p, blksz);
        p += blksz;
    }
    do {
        p = get_sha_block(img, position);
        if (p == NULL)
            break;
        blksz = WOLFBOOT_SHA_BLOCK_SIZE;
        if (position + blksz > img->fw_size)
            blksz = img->fw_size - position;
        wolfTPM2_HashUpdate(&wolftpm_dev, &hash, p, blksz);
        position += blksz;
    } while(position < img->fw_size);
    return wolfTPM2_HashFinish(&wolftpm_dev, &hash, hashBuf, &hashSz);
}

#endif



int wolfBoot_open_image(struct wolfBoot_image *img, uint8_t part)
{
    uint32_t *magic;
    uint32_t *size;
    uint8_t *image;
    if (!img)
        return -1;

#ifdef EXT_FLASH
    hdr_cpy_done = 0; /* reset hdr "open" flag */
#endif

    memset(img, 0, sizeof(struct wolfBoot_image));
    img->part = part;
    if (part == PART_SWAP) {
        img->hdr_ok = 1;
        img->hdr = (void*)WOLFBOOT_PARTITION_SWAP_ADDRESS;
        img->fw_base = img->hdr;
        img->fw_size = WOLFBOOT_SECTOR_SIZE;
        return 0;
    }
#ifdef MMU
    if (part == PART_DTS_BOOT || part == PART_DTS_UPDATE) {
        img->hdr = (part == PART_DTS_BOOT) ? (void*)WOLFBOOT_DTS_BOOT_ADDRESS 
                                           : (void*)WOLFBOOT_DTS_UPDATE_ADDRESS;
        if (PART_IS_EXT(img))
            image = fetch_hdr_cpy(img);
        else
            image = (uint8_t*)img->hdr;
        if (*((uint32_t*)image) != UBOOT_FDT_MAGIC)
            return -1;
        img->hdr_ok = 1;
        img->fw_base = img->hdr;
        /* DTS data is big endian */
        size = (uint32_t*)(image + sizeof(uint32_t));
        img->fw_size = (((*size & 0x000000FF) << 24) |
                        ((*size & 0x0000FF00) <<  8) |
                        ((*size & 0x00FF0000) >>  8) |
                        ((*size & 0xFF000000) >> 24));
        return 0;
    }
#endif
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
    size = (uint32_t *)(image + sizeof (uint32_t));

    if (*size >= WOLFBOOT_PARTITION_SIZE)
       return -1;
    img->hdr_ok = 1;
    img->fw_size = *size;
    img->fw_base = img->hdr + IMAGE_HEADER_SIZE;
    img->trailer = img->hdr + WOLFBOOT_PARTITION_SIZE;
    return 0;
}

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

int wolfBoot_verify_authenticity(struct wolfBoot_image *img)
{
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
    if (wolfBoot_protect_verify_signature(img->sha_hash, stored_signature) != 0)
        return -1;
    img->signature_ok = verification_result;
    return !!!(verification_result);
}

/* Peek at image offset and return static pointer */
/* sz: optional and returns length of peek */
uint8_t* wolfBoot_peek_image(struct wolfBoot_image *img, uint32_t offset, 
    uint32_t* sz)
{
    uint8_t* p = get_sha_block(img, offset);
    if (sz)
        *sz = WOLFBOOT_SHA_BLOCK_SIZE;    
    return p;
}
