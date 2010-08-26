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
#ifndef __ARCH_DESC_H
#define __ARCH_DESC_H

#include <asm/ldt.h>
#include <asm/segment.h>

#ifndef __ASSEMBLY__

#include <linux/preempt.h>
#include <linux/smp.h>
#include <linux/percpu.h>

#include <asm/mmu.h>

struct Xgt_desc_struct {
 unsigned short size;
 unsigned long address __attribute__((packed));
 unsigned short pad;
} __attribute__ ((packed));

struct gdt_page
{
 struct desc_struct gdt[GDT_ENTRIES];
} __attribute__((aligned(PAGE_SIZE)));

#define DESCTYPE_LDT 0x82  
#define DESCTYPE_TSS 0x89  
#define DESCTYPE_TASK 0x85  
#define DESCTYPE_INT 0x8e  
#define DESCTYPE_TRAP 0x8f  
#define DESCTYPE_DPL3 0x60  
#define DESCTYPE_S 0x10  
#define load_TR_desc() native_load_tr_desc()
#define load_gdt(dtr) native_load_gdt(dtr)
#define load_idt(dtr) native_load_idt(dtr)
#define load_tr(tr) __asm__ __volatile("ltr %0"::"m" (tr))
#define load_ldt(ldt) __asm__ __volatile("lldt %0"::"m" (ldt))
#define store_gdt(dtr) native_store_gdt(dtr)
#define store_idt(dtr) native_store_idt(dtr)
#define store_tr(tr) (tr = native_store_tr())
#define store_ldt(ldt) __asm__ ("sldt %0":"=m" (ldt))
#define load_TLS(t, cpu) native_load_tls(t, cpu)
#define set_ldt native_set_ldt
#define write_ldt_entry(dt, entry, a, b) write_dt_entry(dt, entry, a, b)
#define write_gdt_entry(dt, entry, a, b) write_dt_entry(dt, entry, a, b)
#define write_idt_entry(dt, entry, a, b) write_dt_entry(dt, entry, a, b)
#define set_tss_desc(cpu,addr) __set_tss_desc(cpu, GDT_ENTRY_TSS, addr)
#define LDT_entry_a(info)   ((((info)->base_addr & 0x0000ffff) << 16) | ((info)->limit & 0x0ffff))
#define LDT_entry_b(info)   (((info)->base_addr & 0xff000000) |   (((info)->base_addr & 0x00ff0000) >> 16) |   ((info)->limit & 0xf0000) |   (((info)->read_exec_only ^ 1) << 9) |   ((info)->contents << 10) |   (((info)->seg_not_present ^ 1) << 15) |   ((info)->seg_32bit << 22) |   ((info)->limit_in_pages << 23) |   ((info)->useable << 20) |   0x7000)
#define LDT_empty(info) (  (info)->base_addr == 0 &&   (info)->limit == 0 &&   (info)->contents == 0 &&   (info)->read_exec_only == 1 &&   (info)->seg_32bit == 0 &&   (info)->limit_in_pages == 0 &&   (info)->seg_not_present == 1 &&   (info)->useable == 0 )
#else
#define GET_DESC_BASE(idx, gdt, base, lo_w, lo_b, hi_b)   movb idx*8+4(gdt), lo_b;   movb idx*8+7(gdt), hi_b;   shll $16, base;   movw idx*8+2(gdt), lo_w;
#endif
#endif
