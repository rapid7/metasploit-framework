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
#ifndef __ASM_IO_APIC_H
#define __ASM_IO_APIC_H

#include <asm/types.h>
#include <asm/mpspec.h>
#include <asm/apicdef.h>

union IO_APIC_reg_00 {
 u32 raw;
 struct {
 u32 __reserved_2 : 14,
 LTS : 1,
 delivery_type : 1,
 __reserved_1 : 8,
 ID : 8;
 } __attribute__ ((packed)) bits;
};

union IO_APIC_reg_01 {
 u32 raw;
 struct {
 u32 version : 8,
 __reserved_2 : 7,
 PRQ : 1,
 entries : 8,
 __reserved_1 : 8;
 } __attribute__ ((packed)) bits;
};

union IO_APIC_reg_02 {
 u32 raw;
 struct {
 u32 __reserved_2 : 24,
 arbitration : 4,
 __reserved_1 : 4;
 } __attribute__ ((packed)) bits;
};

union IO_APIC_reg_03 {
 u32 raw;
 struct {
 u32 boot_DT : 1,
 __reserved_1 : 31;
 } __attribute__ ((packed)) bits;
};

enum ioapic_irq_destination_types {
 dest_Fixed = 0,
 dest_LowestPrio = 1,
 dest_SMI = 2,
 dest__reserved_1 = 3,
 dest_NMI = 4,
 dest_INIT = 5,
 dest__reserved_2 = 6,
 dest_ExtINT = 7
};

struct IO_APIC_route_entry {
 __u32 vector : 8,
 delivery_mode : 3,
 dest_mode : 1,
 delivery_status : 1,
 polarity : 1,
 irr : 1,
 trigger : 1,
 mask : 1,
 __reserved_2 : 15;

 union { struct { __u32
 __reserved_1 : 24,
 physical_dest : 4,
 __reserved_2 : 4;
 } physical;

 struct { __u32
 __reserved_1 : 24,
 logical_dest : 8;
 } logical;
 } dest;

} __attribute__ ((packed));

#define io_apic_assign_pci_irqs 0

#endif
