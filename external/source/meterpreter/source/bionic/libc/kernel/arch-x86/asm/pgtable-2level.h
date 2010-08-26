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
#ifndef _I386_PGTABLE_2LEVEL_H
#define _I386_PGTABLE_2LEVEL_H

#define pte_ERROR(e)   printk("%s:%d: bad pte %08lx.\n", __FILE__, __LINE__, (e).pte_low)
#define pgd_ERROR(e)   printk("%s:%d: bad pgd %08lx.\n", __FILE__, __LINE__, pgd_val(e))

#define set_pte(pteptr, pteval) native_set_pte(pteptr, pteval)
#define set_pte_at(mm,addr,ptep,pteval) native_set_pte_at(mm, addr, ptep, pteval)
#define set_pmd(pmdptr, pmdval) native_set_pmd(pmdptr, pmdval)
#define set_pte_atomic(pteptr, pteval) set_pte(pteptr,pteval)
#define set_pte_present(mm,addr,ptep,pteval) set_pte_at(mm,addr,ptep,pteval)
#define pte_clear(mm,addr,xp) do { set_pte_at(mm, addr, xp, __pte(0)); } while (0)
#define pmd_clear(xp) do { set_pmd(xp, __pmd(0)); } while (0)
#define native_ptep_get_and_clear(xp) native_local_ptep_get_and_clear(xp)
#define pte_page(x) pfn_to_page(pte_pfn(x))
#define pte_none(x) (!(x).pte_low)
#define pte_pfn(x) (pte_val(x) >> PAGE_SHIFT)
#define pfn_pte(pfn, prot) __pte(((pfn) << PAGE_SHIFT) | pgprot_val(prot))
#define pfn_pmd(pfn, prot) __pmd(((pfn) << PAGE_SHIFT) | pgprot_val(prot))
#define PTE_FILE_MAX_BITS 29
#define pte_to_pgoff(pte)   ((((pte).pte_low >> 1) & 0x1f ) + (((pte).pte_low >> 8) << 5 ))
#define pgoff_to_pte(off)   ((pte_t) { (((off) & 0x1f) << 1) + (((off) >> 5) << 8) + _PAGE_FILE })
#define __swp_type(x) (((x).val >> 1) & 0x1f)
#define __swp_offset(x) ((x).val >> 8)
#define __swp_entry(type, offset) ((swp_entry_t) { ((type) << 1) | ((offset) << 8) })
#define __pte_to_swp_entry(pte) ((swp_entry_t) { (pte).pte_low })
#define __swp_entry_to_pte(x) ((pte_t) { (x).val })
#endif
