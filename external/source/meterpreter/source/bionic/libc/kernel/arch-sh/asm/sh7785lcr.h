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
#ifndef __ASM_SH_RENESAS_SH7785LCR_H
#define __ASM_SH_RENESAS_SH7785LCR_H

#define NOR_FLASH_ADDR 0x00000000
#define NOR_FLASH_SIZE 0x04000000

#define PLD_BASE_ADDR 0x04000000
#define PLD_PCICR (PLD_BASE_ADDR + 0x00)
#define PLD_LCD_BK_CONTR (PLD_BASE_ADDR + 0x02)
#define PLD_LOCALCR (PLD_BASE_ADDR + 0x04)
#define PLD_POFCR (PLD_BASE_ADDR + 0x06)
#define PLD_LEDCR (PLD_BASE_ADDR + 0x08)
#define PLD_SWSR (PLD_BASE_ADDR + 0x0a)
#define PLD_VERSR (PLD_BASE_ADDR + 0x0c)
#define PLD_MMSR (PLD_BASE_ADDR + 0x0e)

#define SM107_MEM_ADDR 0x10000000
#define SM107_MEM_SIZE 0x00e00000
#define SM107_REG_ADDR 0x13e00000
#define SM107_REG_SIZE 0x00200000

#define R8A66597_ADDR 0x08000000
#define CG200_ADDR 0x0c000000
#define PCA9564_ADDR 0x14000000

#define R8A66597_SIZE 0x00000100
#define CG200_SIZE 0x00010000
#define PCA9564_SIZE 0x00000100

#endif

