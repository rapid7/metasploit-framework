/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was automatically generated from a Linux kernel header
 ***   of the same name, to make information necessary for userspace to
 ***   call into the kernel available to libc.  It contains only constants,
 ***   structures, and macros generated from the original header, and thus,
 ***   contains no copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/
#ifndef __MMU_H
#define __MMU_H

typedef unsigned long mm_context_id_t[NR_CPUS];

typedef struct {
 mm_context_id_t id;
 void *vdso;
} mm_context_t;

#define PMB_PASCR 0xff000070
#define PMB_IRMCR 0xff000078

#define PMB_ADDR 0xf6100000
#define PMB_DATA 0xf7100000
#define PMB_ENTRY_MAX 16
#define PMB_E_MASK 0x0000000f
#define PMB_E_SHIFT 8

#define PMB_SZ_16M 0x00000000
#define PMB_SZ_64M 0x00000010
#define PMB_SZ_128M 0x00000080
#define PMB_SZ_512M 0x00000090
#define PMB_SZ_MASK PMB_SZ_512M
#define PMB_C 0x00000008
#define PMB_WT 0x00000001
#define PMB_UB 0x00000200
#define PMB_V 0x00000100

#define PMB_NO_ENTRY (-1)

struct pmb_entry;

struct pmb_entry {
 unsigned long vpn;
 unsigned long ppn;
 unsigned long flags;

 int entry;

 struct pmb_entry *next;

 struct pmb_entry *link;
};

struct pmb_entry *pmb_alloc(unsigned long vpn, unsigned long ppn,
 unsigned long flags);

#endif

