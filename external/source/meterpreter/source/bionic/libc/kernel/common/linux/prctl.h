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
#ifndef _LINUX_PRCTL_H
#define _LINUX_PRCTL_H

#define PR_SET_PDEATHSIG 1  
#define PR_GET_PDEATHSIG 2  

#define PR_GET_DUMPABLE 3
#define PR_SET_DUMPABLE 4

#define PR_GET_UNALIGN 5
#define PR_SET_UNALIGN 6
#define PR_UNALIGN_NOPRINT 1  
#define PR_UNALIGN_SIGBUS 2  

#define PR_GET_KEEPCAPS 7
#define PR_SET_KEEPCAPS 8

#define PR_GET_FPEMU 9
#define PR_SET_FPEMU 10
#define PR_FPEMU_NOPRINT 1  
#define PR_FPEMU_SIGFPE 2  

#define PR_GET_FPEXC 11
#define PR_SET_FPEXC 12
#define PR_FP_EXC_SW_ENABLE 0x80  
#define PR_FP_EXC_DIV 0x010000  
#define PR_FP_EXC_OVF 0x020000  
#define PR_FP_EXC_UND 0x040000  
#define PR_FP_EXC_RES 0x080000  
#define PR_FP_EXC_INV 0x100000  
#define PR_FP_EXC_DISABLED 0  
#define PR_FP_EXC_NONRECOV 1  
#define PR_FP_EXC_ASYNC 2  
#define PR_FP_EXC_PRECISE 3  

#define PR_GET_TIMING 13
#define PR_SET_TIMING 14
#define PR_TIMING_STATISTICAL 0  
#define PR_TIMING_TIMESTAMP 1  

#define PR_SET_NAME 15  
#define PR_GET_NAME 16  

#define PR_GET_ENDIAN 19
#define PR_SET_ENDIAN 20
#define PR_ENDIAN_BIG 0
#define PR_ENDIAN_LITTLE 1  
#define PR_ENDIAN_PPC_LITTLE 2  

#endif
