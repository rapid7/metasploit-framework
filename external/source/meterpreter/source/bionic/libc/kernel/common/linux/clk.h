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
#ifndef __LINUX_CLK_H
#define __LINUX_CLK_H

struct device;

struct clk;

struct clk *clk_get(struct device *dev, const char *id);

struct clk *clk_get_parent(struct clk *clk);

#endif
