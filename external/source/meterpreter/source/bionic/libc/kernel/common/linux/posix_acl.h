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
#ifndef __LINUX_POSIX_ACL_H
#define __LINUX_POSIX_ACL_H

#include <linux/slab.h>

#define ACL_UNDEFINED_ID (-1)

#define ACL_TYPE_ACCESS (0x8000)
#define ACL_TYPE_DEFAULT (0x4000)

#define ACL_USER_OBJ (0x01)
#define ACL_USER (0x02)
#define ACL_GROUP_OBJ (0x04)
#define ACL_GROUP (0x08)
#define ACL_MASK (0x10)
#define ACL_OTHER (0x20)

#define ACL_READ (0x04)
#define ACL_WRITE (0x02)
#define ACL_EXECUTE (0x01)

struct posix_acl_entry {
 short e_tag;
 unsigned short e_perm;
 unsigned int e_id;
};

struct posix_acl {
 atomic_t a_refcount;
 unsigned int a_count;
 struct posix_acl_entry a_entries[0];
};

#define FOREACH_ACL_ENTRY(pa, acl, pe)   for(pa=(acl)->a_entries, pe=pa+(acl)->a_count; pa<pe; pa++)

#endif
