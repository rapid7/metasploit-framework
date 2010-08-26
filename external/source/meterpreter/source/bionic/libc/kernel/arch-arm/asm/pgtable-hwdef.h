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
#ifndef _ASMARM_PGTABLE_HWDEF_H
#define _ASMARM_PGTABLE_HWDEF_H

#define PMD_TYPE_MASK (3 << 0)
#define PMD_TYPE_FAULT (0 << 0)
#define PMD_TYPE_TABLE (1 << 0)
#define PMD_TYPE_SECT (2 << 0)
#define PMD_BIT4 (1 << 4)
#define PMD_DOMAIN(x) ((x) << 5)
#define PMD_PROTECTION (1 << 9)  

#define PMD_SECT_BUFFERABLE (1 << 2)
#define PMD_SECT_CACHEABLE (1 << 3)
#define PMD_SECT_XN (1 << 4)  
#define PMD_SECT_AP_WRITE (1 << 10)
#define PMD_SECT_AP_READ (1 << 11)
#define PMD_SECT_TEX(x) ((x) << 12)  
#define PMD_SECT_APX (1 << 15)  
#define PMD_SECT_S (1 << 16)  
#define PMD_SECT_nG (1 << 17)  
#define PMD_SECT_SUPER (1 << 18)  

#define PMD_SECT_UNCACHED (0)
#define PMD_SECT_BUFFERED (PMD_SECT_BUFFERABLE)
#define PMD_SECT_WT (PMD_SECT_CACHEABLE)
#define PMD_SECT_WB (PMD_SECT_CACHEABLE | PMD_SECT_BUFFERABLE)
#define PMD_SECT_MINICACHE (PMD_SECT_TEX(1) | PMD_SECT_CACHEABLE)
#define PMD_SECT_WBWA (PMD_SECT_TEX(1) | PMD_SECT_CACHEABLE | PMD_SECT_BUFFERABLE)
#define PMD_SECT_NONSHARED_DEV (PMD_SECT_TEX(2))

#define PTE_TYPE_MASK (3 << 0)
#define PTE_TYPE_FAULT (0 << 0)
#define PTE_TYPE_LARGE (1 << 0)
#define PTE_TYPE_SMALL (2 << 0)
#define PTE_TYPE_EXT (3 << 0)  
#define PTE_BUFFERABLE (1 << 2)
#define PTE_CACHEABLE (1 << 3)

#define PTE_EXT_XN (1 << 0)  
#define PTE_EXT_AP_MASK (3 << 4)
#define PTE_EXT_AP0 (1 << 4)
#define PTE_EXT_AP1 (2 << 4)
#define PTE_EXT_AP_UNO_SRO (0 << 4)
#define PTE_EXT_AP_UNO_SRW (PTE_EXT_AP0)
#define PTE_EXT_AP_URO_SRW (PTE_EXT_AP1)
#define PTE_EXT_AP_URW_SRW (PTE_EXT_AP1|PTE_EXT_AP0)
#define PTE_EXT_TEX(x) ((x) << 6)  
#define PTE_EXT_APX (1 << 9)  
#define PTE_EXT_COHERENT (1 << 9)  
#define PTE_EXT_SHARED (1 << 10)  
#define PTE_EXT_NG (1 << 11)  

#define PTE_SMALL_AP_MASK (0xff << 4)
#define PTE_SMALL_AP_UNO_SRO (0x00 << 4)
#define PTE_SMALL_AP_UNO_SRW (0x55 << 4)
#define PTE_SMALL_AP_URO_SRW (0xaa << 4)
#define PTE_SMALL_AP_URW_SRW (0xff << 4)

#endif
