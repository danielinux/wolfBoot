#ifndef MPTABLE_H
#define MPTABLE_H

/* TODO: copied from linux kernel, make our own */

/* Intel MP Floating Pointer Structure */
struct mpf_intel {
	char signature[4];		/* "_MP_"			*/
	unsigned int physptr;		/* Configuration table address	*/
	unsigned char length;		/* Our length (paragraphs)	*/
	unsigned char specification;	/* Specification version	*/
	unsigned char checksum;		/* Checksum (makes sum 0)	*/
	unsigned char feature1;		/* Standard or configuration ?	*/
	unsigned char feature2;		/* Bit7 set for IMCR|PIC	*/
	unsigned char feature3;		/* Unused (0)			*/
	unsigned char feature4;		/* Unused (0)			*/
	unsigned char feature5;		/* Unused (0)			*/
};

#define MPC_SIGNATURE "PCMP"

struct mpc_table {
	char signature[4];
	unsigned short length;		/* Size of table */
	char spec;			/* 0x01 */
	char checksum;
	char oem[8];
	char productid[12];
	unsigned int oemptr;		/* 0 if not present */
	unsigned short oemsize;		/* 0 if not present */
	unsigned short oemcount;
	unsigned int lapic;		/* APIC address */
	unsigned int reserved;
};

/* Followed by entries */

#define	MP_PROCESSOR		0
#define	MP_BUS			1
#define	MP_IOAPIC		2
#define	MP_INTSRC		3
#define	MP_LINTSRC		4
/* Used by IBM NUMA-Q to describe node locality */
#define	MP_TRANSLATION		192

#define CPU_ENABLED		1	/* Processor is available */
#define CPU_BOOTPROCESSOR	2	/* Processor is the boot CPU */

#define CPU_STEPPING_MASK	0x000F
#define CPU_MODEL_MASK		0x00F0
#define CPU_FAMILY_MASK		0x0F00

#define MPC_APIC_USABLE		0x01

struct mpc_ioapic {
	unsigned char type;
	unsigned char apicid;
	unsigned char apicver;
	unsigned char flags;
	unsigned int apicaddr;
};

struct mpc_intsrc {
	unsigned char type;
	unsigned char irqtype;
	unsigned short irqflag;
	unsigned char srcbus;
	unsigned char srcbusirq;
	unsigned char dstapic;
	unsigned char dstirq;
};

struct mpc_lintsrc {
    unsigned char type;
    unsigned char irqtype;
    unsigned short irqflag;
    unsigned char srcbus;
    unsigned char srcbusirq;
	unsigned char dstapic;
	unsigned char lintin;
};

struct mpc_bus {
	unsigned char type;
	unsigned char busid;
	unsigned char bustype[6];
};

enum mp_irq_source_types {
	mp_INT = 0,
	mp_NMI = 1,
	mp_SMI = 2,
	mp_ExtINT = 3
};

struct mpc_cpu {
	unsigned char type;
	unsigned char apicid;		/* Local APIC number */
	unsigned char apicver;		/* Its versions */
	unsigned char cpuflag;
	unsigned int cpufeature;
	unsigned int featureflag;	/* CPUID feature value */
	unsigned int reserved[2];
};

#define MP_IRQPOL_DEFAULT	0x0
#define MP_IRQPOL_ACTIVE_HIGH	0x1
#define MP_IRQPOL_RESERVED	0x2
#define MP_IRQPOL_ACTIVE_LOW	0x3
#define MP_IRQPOL_MASK		0x3

#define MP_IRQTRIG_DEFAULT	0x0
#define MP_IRQTRIG_EDGE		0x4
#define MP_IRQTRIG_RESERVED	0x8
#define MP_IRQTRIG_LEVEL	0xc
#define MP_IRQTRIG_MASK		0xc

#define MP_APIC_ALL	0xFF

#define MP_IOAPIC_NUM_ENTRY 1
#define MP_INTSRC_NUM_ENTRY 14
#define MP_LINTSRC_NUM_ENTRY 2
#define MP_BUS_NUM_ENTRY 1
#define MP_CPU_NUM_ENTRY 1

struct mptable {
    struct mpf_intel mpf;
    struct mpc_table mpc_table;
    struct mpc_cpu mpc_cpu[MP_CPU_NUM_ENTRY];
    struct mpc_bus bus[MP_BUS_NUM_ENTRY];
    struct mpc_ioapic ioapic[MP_IOAPIC_NUM_ENTRY];
    struct mpc_intsrc intsrc[MP_INTSRC_NUM_ENTRY];
    struct mpc_lintsrc lintsrc[MP_LINTSRC_NUM_ENTRY];
} __attribute__((packed));

extern void setup_mptable(void);

#endif /* MPTABLE_H */

