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
#ifndef __LINUX_MTD_MAP_H__
#define __LINUX_MTD_MAP_H__

#include <linux/types.h>
#include <linux/list.h>
#include <linux/string.h>

#include <linux/mtd/compatmac.h>

#include <asm/unaligned.h>
#include <asm/system.h>
#include <asm/io.h>

#define map_bankwidth_is_1(map) (0)

#define map_bankwidth_is_2(map) (0)

#define map_bankwidth_is_4(map) (0)

#define map_calc_words(map) ((map_bankwidth(map) + (sizeof(unsigned long)-1))/ sizeof(unsigned long))

#define map_bankwidth_is_8(map) (0)

#define map_bankwidth_is_16(map) (0)

#define map_bankwidth_is_32(map) (0)

#ifndef map_bankwidth
#error "No bus width supported. What's the point?"
#endif

#define MAX_MAP_LONGS ( ((MAX_MAP_BANKWIDTH*8) + BITS_PER_LONG - 1) / BITS_PER_LONG )

struct map_info {
 char *name;
 unsigned long size;
 unsigned long phys;
#define NO_XIP (-1UL)

 void __iomem *virt;
 void *cached;

 int bankwidth;

 void (*inval_cache)(struct map_info *, unsigned long, ssize_t);

 void (*set_vpp)(struct map_info *, int);

 unsigned long map_priv_1;
 unsigned long map_priv_2;
 void *fldrv_priv;
 struct mtd_chip_driver *fldrv;
};

struct mtd_chip_driver {
 struct mtd_info *(*probe)(struct map_info *map);
 void (*destroy)(struct mtd_info *);
 struct module *module;
 char *name;
 struct list_head list;
};

struct mtd_info *do_map_probe(const char *name, struct map_info *map);

#define ENABLE_VPP(map) do { if(map->set_vpp) map->set_vpp(map, 1); } while(0)
#define DISABLE_VPP(map) do { if(map->set_vpp) map->set_vpp(map, 0); } while(0)

#define INVALIDATE_CACHED_RANGE(map, from, size)   do { if(map->inval_cache) map->inval_cache(map, from, size); } while(0)

#define map_word_andequal(m, a, b, z) map_word_equal(m, z, map_word_and(m, a, b))
#if BITS_PER_LONG >= 64
#endif
#ifdef __LITTLE_ENDIAN
#else
#endif
#if BITS_PER_LONG < 64
#define MAP_FF_LIMIT 4
#else
#define MAP_FF_LIMIT 8
#endif
#if BITS_PER_LONG >= 64
#endif
#if BITS_PER_LONG >= 64
#endif
#define map_read(map, ofs) inline_map_read(map, ofs)
#define map_copy_from(map, to, from, len) inline_map_copy_from(map, to, from, len)
#define map_write(map, datum, ofs) inline_map_write(map, datum, ofs)
#define map_copy_to(map, to, from, len) inline_map_copy_to(map, to, from, len)
#define simple_map_init(map) BUG_ON(!map_bankwidth_supported((map)->bankwidth))
#define map_is_linear(map) ({ (void)(map); 1; })
#endif
