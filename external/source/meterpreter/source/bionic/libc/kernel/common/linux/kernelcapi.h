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
#ifndef __KERNELCAPI_H__
#define __KERNELCAPI_H__

#define CAPI_MAXAPPL 240  
#define CAPI_MAXCONTR 32  
#define CAPI_MAXDATAWINDOW 8

typedef struct kcapi_flagdef {
 int contr;
 int flag;
} kcapi_flagdef;

typedef struct kcapi_carddef {
 char driver[32];
 unsigned int port;
 unsigned irq;
 unsigned int membase;
 int cardnr;
} kcapi_carddef;

#define KCAPI_CMD_TRACE 10
#define KCAPI_CMD_ADDCARD 11  

#define KCAPI_TRACE_OFF 0
#define KCAPI_TRACE_SHORT_NO_DATA 1
#define KCAPI_TRACE_FULL_NO_DATA 2
#define KCAPI_TRACE_SHORT 3
#define KCAPI_TRACE_FULL 4

#endif
