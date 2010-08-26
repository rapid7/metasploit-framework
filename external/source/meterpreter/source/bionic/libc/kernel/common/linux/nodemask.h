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
#ifndef __LINUX_NODEMASK_H
#define __LINUX_NODEMASK_H

#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/bitmap.h>
#include <linux/numa.h>

typedef struct { DECLARE_BITMAP(bits, MAX_NUMNODES); } nodemask_t;

#define node_set(node, dst) __node_set((node), &(dst))
#define node_clear(node, dst) __node_clear((node), &(dst))
#define nodes_setall(dst) __nodes_setall(&(dst), MAX_NUMNODES)
#define nodes_clear(dst) __nodes_clear(&(dst), MAX_NUMNODES)
#define node_isset(node, nodemask) test_bit((node), (nodemask).bits)
#define node_test_and_set(node, nodemask)   __node_test_and_set((node), &(nodemask))
#define nodes_and(dst, src1, src2)   __nodes_and(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define nodes_or(dst, src1, src2)   __nodes_or(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define nodes_xor(dst, src1, src2)   __nodes_xor(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define nodes_andnot(dst, src1, src2)   __nodes_andnot(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define nodes_complement(dst, src)   __nodes_complement(&(dst), &(src), MAX_NUMNODES)
#define nodes_equal(src1, src2)   __nodes_equal(&(src1), &(src2), MAX_NUMNODES)
#define nodes_intersects(src1, src2)   __nodes_intersects(&(src1), &(src2), MAX_NUMNODES)
#define nodes_subset(src1, src2)   __nodes_subset(&(src1), &(src2), MAX_NUMNODES)
#define nodes_empty(src) __nodes_empty(&(src), MAX_NUMNODES)
#define nodes_full(nodemask) __nodes_full(&(nodemask), MAX_NUMNODES)
#define nodes_weight(nodemask) __nodes_weight(&(nodemask), MAX_NUMNODES)
#define nodes_shift_right(dst, src, n)   __nodes_shift_right(&(dst), &(src), (n), MAX_NUMNODES)
#define nodes_shift_left(dst, src, n)   __nodes_shift_left(&(dst), &(src), (n), MAX_NUMNODES)
#define first_node(src) __first_node(&(src))
#define next_node(n, src) __next_node((n), &(src))
#define nodemask_of_node(node)  ({   typeof(_unused_nodemask_arg_) m;   if (sizeof(m) == sizeof(unsigned long)) {   m.bits[0] = 1UL<<(node);   } else {   nodes_clear(m);   node_set((node), m);   }   m;  })
#define first_unset_node(mask) __first_unset_node(&(mask))
#define NODE_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(MAX_NUMNODES)
#if MAX_NUMNODES <= BITS_PER_LONG
#define NODE_MASK_ALL  ((nodemask_t) { {   [BITS_TO_LONGS(MAX_NUMNODES)-1] = NODE_MASK_LAST_WORD  } })
#else
#define NODE_MASK_ALL  ((nodemask_t) { {   [0 ... BITS_TO_LONGS(MAX_NUMNODES)-2] = ~0UL,   [BITS_TO_LONGS(MAX_NUMNODES)-1] = NODE_MASK_LAST_WORD  } })
#endif
#define NODE_MASK_NONE  ((nodemask_t) { {   [0 ... BITS_TO_LONGS(MAX_NUMNODES)-1] = 0UL  } })
#define nodes_addr(src) ((src).bits)
#define nodemask_scnprintf(buf, len, src)   __nodemask_scnprintf((buf), (len), &(src), MAX_NUMNODES)
#define nodemask_parse(ubuf, ulen, dst)   __nodemask_parse((ubuf), (ulen), &(dst), MAX_NUMNODES)
#define nodelist_scnprintf(buf, len, src)   __nodelist_scnprintf((buf), (len), &(src), MAX_NUMNODES)
#define nodelist_parse(buf, dst) __nodelist_parse((buf), &(dst), MAX_NUMNODES)
#define node_remap(oldbit, old, new)   __node_remap((oldbit), &(old), &(new), MAX_NUMNODES)
#define nodes_remap(dst, src, old, new)   __nodes_remap(&(dst), &(src), &(old), &(new), MAX_NUMNODES)
#if MAX_NUMNODES > 1
#define for_each_node_mask(node, mask)   for ((node) = first_node(mask);   (node) < MAX_NUMNODES;   (node) = next_node((node), (mask)))
#else
#define for_each_node_mask(node, mask)   if (!nodes_empty(mask))   for ((node) = 0; (node) < 1; (node)++)
#endif

#if MAX_NUMNODES > 1
#define num_online_nodes() nodes_weight(node_online_map)
#define num_possible_nodes() nodes_weight(node_possible_map)
#define node_online(node) node_isset((node), node_online_map)
#define node_possible(node) node_isset((node), node_possible_map)
#define first_online_node first_node(node_online_map)
#define next_online_node(nid) next_node((nid), node_online_map)
#else
#define num_online_nodes() 1
#define num_possible_nodes() 1
#define node_online(node) ((node) == 0)
#define node_possible(node) ((node) == 0)
#define first_online_node 0
#define next_online_node(nid) (MAX_NUMNODES)
#endif

#define any_online_node(mask)  ({   int node;   for_each_node_mask(node, (mask))   if (node_online(node))   break;   node;  })

#define node_set_online(node) set_bit((node), node_online_map.bits)
#define node_set_offline(node) clear_bit((node), node_online_map.bits)

#define for_each_node(node) for_each_node_mask((node), node_possible_map)
#define for_each_online_node(node) for_each_node_mask((node), node_online_map)

#endif
