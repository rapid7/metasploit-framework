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
#ifndef _ASM_SH_SH7760FB_H
#define _ASM_SH_SH7760FB_H

#define SH7760FB_PALETTE_MASK 0x00f8fcf8

#define SH7760FB_DMA_MASK 0x0C000000

#define LDPR(x) (((x) << 2))

#define LDICKR 0x400
#define LDMTR 0x402

#define LDDFR 0x404
#define LDDFR_PABD (1 << 8)
#define LDDFR_COLOR_MASK 0x7F
#define LDSMR 0x406
#define LDSMR_ROT (1 << 13)
#define LDSARU 0x408
#define LDSARL 0x40c
#define LDLAOR 0x410
#define LDPALCR 0x412
#define LDPALCR_PALS (1 << 4)
#define LDPALCR_PALEN (1 << 0)
#define LDHCNR 0x414
#define LDHSYNR 0x416
#define LDVDLNR 0x418
#define LDVTLNR 0x41a
#define LDVSYNR 0x41c
#define LDACLNR 0x41e
#define LDINTR 0x420
#define LDPMMR 0x424
#define LDPSPR 0x426
#define LDCNTR 0x428
#define LDCNTR_DON (1 << 0)
#define LDCNTR_DON2 (1 << 4)

#define LDINTR_VINTSEL (1 << 12)
#define LDINTR_VINTE (1 << 8)
#define LDINTR_VINTS (1 << 0)
#define VINT_START (LDINTR_VINTSEL)
#define VINT_CHECK (LDINTR_VINTS)

#define LDMTR_FLMPOL (1 << 15)

#define LDMTR_CL1POL (1 << 14)

#define LDMTR_DISPEN_LOWACT (1 << 13)

#define LDMTR_DPOL_LOWACT (1 << 12)

#define LDMTR_MCNT (1 << 10)

#define LDMTR_CL1CNT (1 << 9)

#define LDMTR_CL2CNT (1 << 8)

#define LDMTR_STN_MONO_4 0x00
#define LDMTR_STN_MONO_8 0x01
#define LDMTR_STN_COLOR_4 0x08
#define LDMTR_STN_COLOR_8 0x09
#define LDMTR_STN_COLOR_12 0x0A
#define LDMTR_STN_COLOR_16 0x0B
#define LDMTR_DSTN_MONO_8 0x11
#define LDMTR_DSTN_MONO_16 0x13
#define LDMTR_DSTN_COLOR_8 0x19
#define LDMTR_DSTN_COLOR_12 0x1A
#define LDMTR_DSTN_COLOR_16 0x1B
#define LDMTR_TFT_COLOR_16 0x2B

#define LDDFR_1BPP_MONO 0x00
#define LDDFR_2BPP_MONO 0x01
#define LDDFR_4BPP_MONO 0x02
#define LDDFR_6BPP_MONO 0x04
#define LDDFR_4BPP 0x0A
#define LDDFR_8BPP 0x0C
#define LDDFR_16BPP_RGB555 0x1D
#define LDDFR_16BPP_RGB565 0x2D

#define LCDC_CLKSRC_BUSCLOCK 0
#define LCDC_CLKSRC_PERIPHERAL 1
#define LCDC_CLKSRC_EXTERNAL 2

#define LDICKR_CLKSRC(x)   (((x) & 3) << 12)

#define LDICKR_CLKDIV(x)   ((x) & 0x1f)

struct sh7760fb_platdata {

 struct fb_videomode *def_mode;

 u16 ldmtr;

 u16 lddfr;

 u16 ldpmmr;
 u16 ldpspr;

 u16 ldaclnr;

 u16 ldickr;

 int rotate;

 int novsync;

 void (*blank) (int);
};

#endif
