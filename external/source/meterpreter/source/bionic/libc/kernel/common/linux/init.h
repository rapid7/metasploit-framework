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
#ifndef _LINUX_INIT_H
#define _LINUX_INIT_H

#include <linux/compiler.h>

#define __init __attribute__ ((__section__ (".init.text")))
#define __initdata __attribute__ ((__section__ (".init.data")))
#define __exitdata __attribute__ ((__section__(".exit.data")))
#define __exit_call __attribute_used__ __attribute__ ((__section__ (".exitcall.exit")))

#ifdef MODULE
#define __exit __attribute__ ((__section__(".exit.text")))
#else
#define __exit __attribute_used__ __attribute__ ((__section__(".exit.text")))
#endif

#define __INIT .section ".init.text","ax"
#define __FINIT .previous
#define __INITDATA .section ".init.data","aw"

#ifndef __ASSEMBLY__

typedef int (*initcall_t)(void);
typedef void (*exitcall_t)(void);

#endif

#ifndef MODULE

#ifndef __ASSEMBLY__

#define __define_initcall(level,fn)   static initcall_t __initcall_##fn __attribute_used__   __attribute__((__section__(".initcall" level ".init"))) = fn

#define core_initcall(fn) __define_initcall("1",fn)
#define postcore_initcall(fn) __define_initcall("2",fn)
#define arch_initcall(fn) __define_initcall("3",fn)
#define subsys_initcall(fn) __define_initcall("4",fn)
#define fs_initcall(fn) __define_initcall("5",fn)
#define device_initcall(fn) __define_initcall("6",fn)
#define late_initcall(fn) __define_initcall("7",fn)

#define __initcall(fn) device_initcall(fn)

#define __exitcall(fn)   static exitcall_t __exitcall_##fn __exit_call = fn

#define console_initcall(fn)   static initcall_t __initcall_##fn   __attribute_used__ __attribute__((__section__(".con_initcall.init")))=fn

#define security_initcall(fn)   static initcall_t __initcall_##fn   __attribute_used__ __attribute__((__section__(".security_initcall.init"))) = fn

struct obs_kernel_param {
 const char *str;
 int (*setup_func)(char *);
 int early;
};

#define __setup_param(str, unique_id, fn, early)   static char __setup_str_##unique_id[] __initdata = str;   static struct obs_kernel_param __setup_##unique_id   __attribute_used__   __attribute__((__section__(".init.setup")))   __attribute__((aligned((sizeof(long)))))   = { __setup_str_##unique_id, fn, early }

#define __setup_null_param(str, unique_id)   __setup_param(str, unique_id, NULL, 0)

#define __setup(str, fn)   __setup_param(str, fn, fn, 0)

#define __obsolete_setup(str)   __setup_null_param(str, __LINE__)

#define early_param(str, fn)   __setup_param(str, fn, fn, 1)

#endif

#define module_init(x) __initcall(x);

#define module_exit(x) __exitcall(x);

#else

#define core_initcall(fn) module_init(fn)
#define postcore_initcall(fn) module_init(fn)
#define arch_initcall(fn) module_init(fn)
#define subsys_initcall(fn) module_init(fn)
#define fs_initcall(fn) module_init(fn)
#define device_initcall(fn) module_init(fn)
#define late_initcall(fn) module_init(fn)

#define security_initcall(fn) module_init(fn)

#define module_init(initfn)   static inline initcall_t __inittest(void)   { return initfn; }   int init_module(void) __attribute__((alias(#initfn)));

#define module_exit(exitfn)   static inline exitcall_t __exittest(void)   { return exitfn; }   void cleanup_module(void) __attribute__((alias(#exitfn)));

#define __setup_param(str, unique_id, fn)  
#define __setup_null_param(str, unique_id)  
#define __setup(str, func)  
#define __obsolete_setup(str)  
#endif

#define __nosavedata __attribute__ ((__section__ (".data.nosave")))

#define __init_or_module __init
#define __initdata_or_module __initdata

#define __devinit __init
#define __devinitdata __initdata
#define __devexit __exit
#define __devexitdata __exitdata

#define __cpuinit __init
#define __cpuinitdata __initdata
#define __cpuexit __exit
#define __cpuexitdata __exitdata

#define __meminit __init
#define __meminitdata __initdata
#define __memexit __exit
#define __memexitdata __exitdata

#ifdef MODULE
#define __devexit_p(x) x
#else
#define __devexit_p(x) NULL
#endif

#ifdef MODULE
#define __exit_p(x) x
#else
#define __exit_p(x) NULL
#endif

#endif
