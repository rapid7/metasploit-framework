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
#ifndef _ASM_X86_TERMIOS_H
#define _ASM_X86_TERMIOS_H

#include <asm/termbits.h>
#include <asm/ioctls.h>

struct winsize {
 unsigned short ws_row;
 unsigned short ws_col;
 unsigned short ws_xpixel;
 unsigned short ws_ypixel;
};

#define NCC 8
struct termio {
 unsigned short c_iflag;
 unsigned short c_oflag;
 unsigned short c_cflag;
 unsigned short c_lflag;
 unsigned char c_line;
 unsigned char c_cc[NCC];
};

#define TIOCM_LE 0x001
#define TIOCM_DTR 0x002
#define TIOCM_RTS 0x004
#define TIOCM_ST 0x008
#define TIOCM_SR 0x010
#define TIOCM_CTS 0x020
#define TIOCM_CAR 0x040
#define TIOCM_RNG 0x080
#define TIOCM_DSR 0x100
#define TIOCM_CD TIOCM_CAR
#define TIOCM_RI TIOCM_RNG
#define TIOCM_OUT1 0x2000
#define TIOCM_OUT2 0x4000
#define TIOCM_LOOP 0x8000

#define N_TTY 0
#define N_SLIP 1
#define N_MOUSE 2
#define N_PPP 3
#define N_STRIP 4
#define N_AX25 5
#define N_X25 6  
#define N_6PACK 7
#define N_MASC 8  
#define N_R3964 9  
#define N_PROFIBUS_FDL 10  
#define N_IRDA 11  
#define N_SMSBLOCK 12  
#define N_HDLC 13  
#define N_SYNC_PPP 14
#define N_HCI 15  

#endif
