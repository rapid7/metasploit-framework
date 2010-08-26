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
#ifndef _I2C_SH7760_H_
#define _I2C_SH7760_H_

#define SH7760_I2C_DEVNAME "sh7760-i2c"

#define SH7760_I2C0_MMIO 0xFE140000
#define SH7760_I2C0_MMIOEND 0xFE14003B
#define SH7760_I2C0_IRQ 62

#define SH7760_I2C1_MMIO 0xFE150000
#define SH7760_I2C1_MMIOEND 0xFE15003B
#define SH7760_I2C1_IRQ 63

struct sh7760_i2c_platdata {
 unsigned int speed_khz;
};

#endif
