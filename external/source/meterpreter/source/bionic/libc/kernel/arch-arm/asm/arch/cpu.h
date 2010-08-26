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
#ifndef __ASM_ARCH_OMAP_CPU_H
#define __ASM_ARCH_OMAP_CPU_H

#define omap2_cpu_rev() ((system_rev >> 8) & 0x0f)

#undef MULTI_OMAP1
#undef MULTI_OMAP2
#undef OMAP_NAME

#define GET_OMAP_CLASS (system_rev & 0xff)

#define IS_OMAP_CLASS(class, id)  static inline int is_omap ##class (void)  {   return (GET_OMAP_CLASS == (id)) ? 1 : 0;  }

#define GET_OMAP_SUBCLASS ((system_rev >> 20) & 0x0fff)

#define IS_OMAP_SUBCLASS(subclass, id)  static inline int is_omap ##subclass (void)  {   return (GET_OMAP_SUBCLASS == (id)) ? 1 : 0;  }

#define cpu_is_omap7xx() 0
#define cpu_is_omap15xx() 0
#define cpu_is_omap16xx() 0
#define cpu_is_omap24xx() 0
#define cpu_is_omap242x() 0
#define cpu_is_omap243x() 0
#ifdef MULTI_OMAP1
#else
#endif
#define GET_OMAP_TYPE ((system_rev >> 16) & 0xffff)
#define IS_OMAP_TYPE(type, id)  static inline int is_omap ##type (void)  {   return (GET_OMAP_TYPE == (id)) ? 1 : 0;  }
#define cpu_is_omap310() 0
#define cpu_is_omap730() 0
#define cpu_is_omap1510() 0
#define cpu_is_omap1610() 0
#define cpu_is_omap5912() 0
#define cpu_is_omap1611() 0
#define cpu_is_omap1621() 0
#define cpu_is_omap1710() 0
#define cpu_is_omap2420() 0
#define cpu_is_omap2422() 0
#define cpu_is_omap2423() 0
#define cpu_is_omap2430() 0
#ifdef MULTI_OMAP1
#else
#endif
#define cpu_class_is_omap1() (cpu_is_omap730() || cpu_is_omap15xx() ||   cpu_is_omap16xx())
#define cpu_class_is_omap2() cpu_is_omap24xx()
#endif
