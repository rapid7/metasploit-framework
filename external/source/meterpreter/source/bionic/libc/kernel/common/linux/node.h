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
#ifndef _LINUX_NODE_H_
#define _LINUX_NODE_H_

#include <linux/sysdev.h>
#include <linux/cpumask.h>

struct node {
 struct sys_device sysdev;
};

#define to_node(sys_device) container_of(sys_device, struct node, sysdev)
#endif
