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
#ifndef __ASM_SH_MOBILE_LCDC_H__
#define __ASM_SH_MOBILE_LCDC_H__

#include <linux/fb.h>

enum { RGB8,
 RGB9,
 RGB12A,
 RGB12B,
 RGB16,
 RGB18,
 RGB24,
 SYS8A,
 SYS8B,
 SYS8C,
 SYS8D,
 SYS9,
 SYS12,
 SYS16A,
 SYS16B,
 SYS16C,
 SYS18,
 SYS24 };

enum { LCDC_CHAN_DISABLED = 0,
 LCDC_CHAN_MAINLCD,
 LCDC_CHAN_SUBLCD };

enum { LCDC_CLK_BUS, LCDC_CLK_PERIPHERAL, LCDC_CLK_EXTERNAL };

struct sh_mobile_lcdc_sys_bus_cfg {
 unsigned long ldmt2r;
 unsigned long ldmt3r;
};

struct sh_mobile_lcdc_sys_bus_ops {
 void (*write_index)(void *handle, unsigned long data);
 void (*write_data)(void *handle, unsigned long data);
 unsigned long (*read_data)(void *handle);
};

struct sh_mobile_lcdc_board_cfg {
 void *board_data;
 int (*setup_sys)(void *board_data, void *sys_ops_handle,
 struct sh_mobile_lcdc_sys_bus_ops *sys_ops);
 void (*display_on)(void *board_data);
 void (*display_off)(void *board_data);
};

struct sh_mobile_lcdc_lcd_size_cfg {
 unsigned long width;
 unsigned long height;
};

struct sh_mobile_lcdc_chan_cfg {
 int chan;
 int bpp;
 int interface_type;
 int clock_divider;
 struct fb_videomode lcd_cfg;
 struct sh_mobile_lcdc_lcd_size_cfg lcd_size_cfg;
 struct sh_mobile_lcdc_board_cfg board_cfg;
 struct sh_mobile_lcdc_sys_bus_cfg sys_bus_cfg;
};

struct sh_mobile_lcdc_info {
 unsigned long lddckr;
 int clock_source;
 struct sh_mobile_lcdc_chan_cfg ch[2];
};

#endif
