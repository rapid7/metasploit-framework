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
#ifndef __ASM_PROC_DOMAIN_H
#define __ASM_PROC_DOMAIN_H

#define DOMAIN_KERNEL 0
#define DOMAIN_TABLE 0
#define DOMAIN_USER 1
#define DOMAIN_IO 2

#define DOMAIN_NOACCESS 0
#define DOMAIN_CLIENT 1
#define DOMAIN_MANAGER 3

#define domain_val(dom,type) ((type) << (2*(dom)))

#ifndef __ASSEMBLY__

#define set_domain(x) do { } while (0)
#define modify_domain(dom,type) do { } while (0)

#endif
#endif
