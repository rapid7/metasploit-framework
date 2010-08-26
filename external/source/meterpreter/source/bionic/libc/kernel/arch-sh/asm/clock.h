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
#ifndef __ASM_SH_CLOCK_H
#define __ASM_SH_CLOCK_H

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/clk.h>
#include <linux/err.h>

struct clk;

struct clk_ops {
 void (*init)(struct clk *clk);
 void (*enable)(struct clk *clk);
 void (*disable)(struct clk *clk);
 void (*recalc)(struct clk *clk);
 int (*set_rate)(struct clk *clk, unsigned long rate, int algo_id);
 long (*round_rate)(struct clk *clk, unsigned long rate);
};

struct clk {
 struct list_head node;
 const char *name;
 int id;
 struct module *owner;

 struct clk *parent;
 struct clk_ops *ops;

 struct kref kref;

 unsigned long rate;
 unsigned long flags;
 unsigned long arch_flags;
};

#define CLK_ALWAYS_ENABLED (1 << 0)
#define CLK_RATE_PROPAGATES (1 << 1)

enum clk_sh_algo_id {
 NO_CHANGE = 0,

 IUS_N1_N1,
 IUS_322,
 IUS_522,
 IUS_N11,

 SB_N1,

 SB3_N1,
 SB3_32,
 SB3_43,
 SB3_54,

 BP_N1,

 IP_N1,
};
#endif
