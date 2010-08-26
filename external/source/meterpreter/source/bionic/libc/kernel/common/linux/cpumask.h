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
#ifndef __LINUX_CPUMASK_H
#define __LINUX_CPUMASK_H

#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/bitmap.h>

typedef struct { DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;

#define cpu_set(cpu, dst) __cpu_set((cpu), &(dst))
#define cpu_clear(cpu, dst) __cpu_clear((cpu), &(dst))
#define cpus_setall(dst) __cpus_setall(&(dst), NR_CPUS)
#define cpus_clear(dst) __cpus_clear(&(dst), NR_CPUS)
#define cpu_isset(cpu, cpumask) test_bit((cpu), (cpumask).bits)
#define cpu_test_and_set(cpu, cpumask) __cpu_test_and_set((cpu), &(cpumask))
#define cpus_and(dst, src1, src2) __cpus_and(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_or(dst, src1, src2) __cpus_or(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_xor(dst, src1, src2) __cpus_xor(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_andnot(dst, src1, src2)   __cpus_andnot(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_complement(dst, src) __cpus_complement(&(dst), &(src), NR_CPUS)
#define cpus_equal(src1, src2) __cpus_equal(&(src1), &(src2), NR_CPUS)
#define cpus_intersects(src1, src2) __cpus_intersects(&(src1), &(src2), NR_CPUS)
#define cpus_subset(src1, src2) __cpus_subset(&(src1), &(src2), NR_CPUS)
#define cpus_empty(src) __cpus_empty(&(src), NR_CPUS)
#define cpus_full(cpumask) __cpus_full(&(cpumask), NR_CPUS)
#define cpus_weight(cpumask) __cpus_weight(&(cpumask), NR_CPUS)
#define cpus_shift_right(dst, src, n)   __cpus_shift_right(&(dst), &(src), (n), NR_CPUS)
#define cpus_shift_left(dst, src, n)   __cpus_shift_left(&(dst), &(src), (n), NR_CPUS)
#define first_cpu(src) 0
#define next_cpu(n, src) 1
#define cpumask_of_cpu(cpu)  ({   typeof(_unused_cpumask_arg_) m;   if (sizeof(m) == sizeof(unsigned long)) {   m.bits[0] = 1UL<<(cpu);   } else {   cpus_clear(m);   cpu_set((cpu), m);   }   m;  })
#define CPU_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(NR_CPUS)
#if NR_CPUS <= BITS_PER_LONG
#define CPU_MASK_ALL  (cpumask_t) { {   [BITS_TO_LONGS(NR_CPUS)-1] = CPU_MASK_LAST_WORD  } }
#else
#define CPU_MASK_ALL  (cpumask_t) { {   [0 ... BITS_TO_LONGS(NR_CPUS)-2] = ~0UL,   [BITS_TO_LONGS(NR_CPUS)-1] = CPU_MASK_LAST_WORD  } }
#endif
#define CPU_MASK_NONE  (cpumask_t) { {   [0 ... BITS_TO_LONGS(NR_CPUS)-1] = 0UL  } }
#define CPU_MASK_CPU0  (cpumask_t) { {   [0] = 1UL  } }
#define cpus_addr(src) ((src).bits)
#define cpumask_scnprintf(buf, len, src)   __cpumask_scnprintf((buf), (len), &(src), NR_CPUS)
#define cpumask_parse(ubuf, ulen, dst)   __cpumask_parse((ubuf), (ulen), &(dst), NR_CPUS)
#define cpulist_scnprintf(buf, len, src)   __cpulist_scnprintf((buf), (len), &(src), NR_CPUS)
#define cpulist_parse(buf, dst) __cpulist_parse((buf), &(dst), NR_CPUS)
#define cpu_remap(oldbit, old, new)   __cpu_remap((oldbit), &(old), &(new), NR_CPUS)
#define cpus_remap(dst, src, old, new)   __cpus_remap(&(dst), &(src), &(old), &(new), NR_CPUS)
#if NR_CPUS > 1
#define for_each_cpu_mask(cpu, mask)   for ((cpu) = first_cpu(mask);   (cpu) < NR_CPUS;   (cpu) = next_cpu((cpu), (mask)))
#else
#define for_each_cpu_mask(cpu, mask)   for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#endif

#if NR_CPUS > 1
#define num_online_cpus() cpus_weight(cpu_online_map)
#define num_possible_cpus() cpus_weight(cpu_possible_map)
#define num_present_cpus() cpus_weight(cpu_present_map)
#define cpu_online(cpu) cpu_isset((cpu), cpu_online_map)
#define cpu_possible(cpu) cpu_isset((cpu), cpu_possible_map)
#define cpu_present(cpu) cpu_isset((cpu), cpu_present_map)
#else
#define num_online_cpus() 1
#define num_possible_cpus() 1
#define num_present_cpus() 1
#define cpu_online(cpu) ((cpu) == 0)
#define cpu_possible(cpu) ((cpu) == 0)
#define cpu_present(cpu) ((cpu) == 0)
#endif

#define highest_possible_processor_id() 0
#define any_online_cpu(mask) 0

#define for_each_possible_cpu(cpu) for_each_cpu_mask((cpu), cpu_possible_map)
#define for_each_online_cpu(cpu) for_each_cpu_mask((cpu), cpu_online_map)
#define for_each_present_cpu(cpu) for_each_cpu_mask((cpu), cpu_present_map)

#endif
