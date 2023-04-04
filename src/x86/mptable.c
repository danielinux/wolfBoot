#include <stdint.h>
#include <string.h>
#include "x86/mptable.h"
#include "printf.h"
#define LOCAL_APIC_ID 0xfee00020
#define LOCAL_APIC_VER 0xfee00030
/* TODO: support multiprocessor */

#define MPTABLE_LOAD_BASE 0x100

struct mptable mp = {
    .mpf = {
        .signature = "_MP_",
        .physptr = (int)MPTABLE_LOAD_BASE + sizeof(struct mpf_intel),
        .length = 1,
        .specification = 1,
        .checksum = 0x12,
        .feature1 = 0,
        .feature2 = 1 << 7,
        .feature3 = 0,
        .feature4 = 0,
        .feature5 = 0
    },
    .mpc_table = {
        .signature = MPC_SIGNATURE,
        .length = sizeof(struct mpc_table) +
            sizeof(struct mpc_cpu) * MP_CPU_NUM_ENTRY +
            sizeof(struct mpc_bus) * MP_BUS_NUM_ENTRY +
            sizeof(struct mpc_ioapic) * MP_IOAPIC_NUM_ENTRY +
            sizeof(struct mpc_intsrc) * MP_INTSRC_NUM_ENTRY +
            sizeof(struct mpc_lintsrc) * MP_LINTSRC_NUM_ENTRY,
        .spec = 0x01,
        .checksum = 0x55,
        .oem = { "wolfSSL" },
        .productid = { "wolfBoot" },
        .oemptr = 0,
        .oemsize = 0,
        .oemcount = 0,
        .lapic = 0xfee00000,
        .reserved = 0
    },
    .mpc_cpu = {
        {
            /* filled by bios */
        }
    },
    .bus = {
        {
            .type = MP_BUS,
            .busid = 0,
            .bustype = "PCI"
        }
    },
    .ioapic = {
        {
            .type = MP_IOAPIC,
            .apicid = 0x0,
            .apicver = 0x20,
            .flags = MPC_APIC_USABLE,
            .apicaddr = 0xfec00000,
        }
    },
    .intsrc = {
        {
            .type = MP_INTSRC,
            .irqtype = mp_INT, /* TODO: check */
            .irqflag = MP_IRQPOL_ACTIVE_HIGH,
            .srcbus = 0x0,
            .srcbusirq = (0x2 << 2) | 0x0,
            .dstapic = 0x0,
            .dstirq = 0x0b,
        },
        {
            .type = MP_INTSRC,
            .irqtype = mp_INT, /* TODO: check */
            .irqflag = MP_IRQPOL_ACTIVE_HIGH,
            .srcbus = 0x0,
            .srcbusirq = (0x3 << 2) | 0x0,
            .dstapic = 0x0,
            .dstirq = 0x0b,
        },
        {
            .type = MP_INTSRC,
            .irqtype = mp_INT, /* TODO: check */
            .irqflag = MP_IRQPOL_ACTIVE_HIGH,
            .srcbus = 0x0,
            .srcbusirq = (0x1f << 2) | 0x0,
            .dstapic = 0x0,
            .dstirq = 0x0a,
        },
        {
            .type = MP_INTSRC,
            .irqtype = mp_INT, /* TODO: check */
            .irqflag = 0,
            .srcbus = 0x0,
            .srcbusirq = (0x00 << 2) | 0x0,
            .dstapic = 0x0,
            .dstirq = 0x02,
        },
        {
            .type = MP_INTSRC,
            .irqtype = mp_INT, /* TODO: check */
            .irqflag = 0,
            .srcbus = 0x1,
            .srcbusirq = (0x00 << 2) | 0x1,
            .dstapic = 0x0,
            .dstirq = 0x01,
        },
        {
            .type = MP_INTSRC,
            .irqtype = mp_INT, /* TODO: check */
            .irqflag = 0,
            .srcbus = 0x1,
            .srcbusirq = (0x00 << 2) | 0x3,
            .dstapic = 0x0,
            .dstirq = 0x03,
        },
        {
            .type = MP_INTSRC,
            .irqtype = mp_INT, /* TODO: check */
            .irqflag = 0,
            .srcbus = 0x1,
            .srcbusirq = (0x01 << 2) | 0x0,
            .dstapic = 0x0,
            .dstirq = 0x04,
        },
        {
            .type = MP_INTSRC,
            .irqtype = mp_INT, /* TODO: check */
            .irqflag = 0,
            .srcbus = 0x1,
            .srcbusirq = (0x01 << 2) | 0x2,
            .dstapic = 0x0,
            .dstirq = 0x06,
        },
        {
            .type = MP_INTSRC,
            .irqtype = mp_INT, /* TODO: check */
            .irqflag = 0,
            .srcbus = 0x1,
            .srcbusirq = (0x01 << 2) | 0x3,
            .dstapic = 0x0,
            .dstirq = 0x07,
        },
        {
            .type = MP_INTSRC,
            .irqtype = mp_INT, /* TODO: check */
            .irqflag = 0,
            .srcbus = 0x1,
            .srcbusirq = (0x02 << 2) | 0x0,
            .dstapic = 0x0,
            .dstirq = 0x08,
        },
        {
            .type = MP_INTSRC,
            .irqtype = mp_INT, /* TODO: check */
            .irqflag = 0,
            .srcbus = 0x1,
            .srcbusirq = (0x03 << 2) | 0x0,
            .dstapic = 0x0,
            .dstirq = 0x0c,
        },
        {
            .type = MP_INTSRC,
            .irqtype = mp_INT, /* TODO: check */
            .irqflag = 0,
            .srcbus = 0x1,
            .srcbusirq = (0x03 << 2) | 0x1,
            .dstapic = 0x0,
            .dstirq = 0x0d,
        },
        {
            .type = MP_INTSRC,
            .irqtype = mp_INT, /* TODO: check */
            .irqflag = 0,
            .srcbus = 0x1,
            .srcbusirq = (0x03 << 2) | 0x2,
            .dstapic = 0x0,
            .dstirq = 0x0e,
        },
        {
            .type = MP_INTSRC,
            .irqtype = mp_INT, /* TODO: check */
            .irqflag = 0,
            .srcbus = 0x1,
            .srcbusirq = (0x03 << 2) | 0x3,
            .dstapic = 0x0,
            .dstirq = 0x0f,
        },
    },
    .lintsrc = {
        {
            .type = MP_LINTSRC,
            .irqtype = mp_ExtINT, /* TODO: check table 4.11 */
            .irqflag = 0,
            .srcbus = 0x1,
            .srcbusirq = (0x00 << 2) | 0x0,
            .dstapic = 0x0,
            .lintin = 0x00,
        },
        {
            .type = MP_LINTSRC,
            .irqtype = mp_INT, /* TODO: check table 4.11 */
            .irqflag = 0,
            .srcbus = 0x1,
            .srcbusirq = (0x00 << 2) | 0x0,
            .dstapic = 0xFF,
            .lintin = 0x01,
        }
    }
};



/* TODO: move in x86_hal? */
#define barrier()   __asm__ __volatile__ ("":::"memory");


unsigned int get_cpuid(int eax_value) {
    unsigned int id;
    asm("mov %1, %%eax\n\t"
        "cpuid\n\t"
        "mov %%ebx, %0\n\t"
        : "=r" (id)
        : "r" (eax_value)
        : "%eax", "%ebx", "%ecx", "%edx");
    return id;
}

void *_memcpy(void *dst, const void *src, size_t n)
{
    size_t i;
    const char *s = (const char *)src;
    char *d = (char *)dst;

    for (i = 0; i < n; i++) {
        d[i] = s[i];
    }

    return dst;
}

void mmio_write32(volatile uint32_t *address, uint32_t value)
{
    *address = value;
    barrier();
}

uint32_t mmio_read32(volatile uint32_t *address)
{
    uint32_t ret;

    ret = *address;
    barrier();
    return ret;
}

static void calc_checksum(struct mptable *mp)
{
    uint8_t checksum = 0;
    unsigned int i;
    uint8_t *ptr;

    mp->mpc_table.checksum = 0;
    ptr = (uint8_t*)&mp->mpc_table;

    for (i = 0; i < sizeof(struct mptable) - sizeof(struct mpf_intel); i++, ptr++) {
        checksum += *ptr;
    }

    mp->mpc_table.checksum = (uint8_t)(-((int8_t)checksum));
}

void setup_mptable(void)
{
    uint32_t apic_id, apic_ver;
    uint32_t cpupid_sign;
    struct mptable *_mp;

    apic_id = mmio_read32((uint32_t*)LOCAL_APIC_ID);
    apic_id >>= 24;
    wolfBoot_printf("apic id: %08x", apic_id);
    wolfBoot_printf("\n");

    apic_ver = mmio_read32((uint32_t*)LOCAL_APIC_VER);
    apic_ver &= 0xff;
    wolfBoot_printf("apic ver: %08x", apic_ver);
    wolfBoot_printf("\n");

    cpupid_sign = get_cpuid(0x1);
    /* setup interrupt line 16 */
    _memcpy((uint8_t*)MPTABLE_LOAD_BASE, (uint8_t*)&mp, sizeof(struct mptable));
    _mp = (struct mptable *)MPTABLE_LOAD_BASE;
    _mp->mpc_cpu[0].apicid = apic_id;
    _mp->mpc_cpu[0].apicver = (uint8_t)apic_ver;
    _mp->mpc_cpu[0].cpuflag = 0x3; /* bp | enabled */
    _mp->mpc_cpu[0].cpufeature = cpupid_sign;
    _mp->mpc_cpu[0].featureflag = 0;
    _mp->mpc_cpu[0].reserved[0] = _mp->mpc_cpu[0].reserved[1] = 0;
    calc_checksum(_mp);
}
