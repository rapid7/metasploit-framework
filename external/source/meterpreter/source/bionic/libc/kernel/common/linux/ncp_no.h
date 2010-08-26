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
#ifndef _NCP_NO
#define _NCP_NO

#define aRONLY (__constant_cpu_to_le32(1))
#define aHIDDEN (__constant_cpu_to_le32(2))
#define aSYSTEM (__constant_cpu_to_le32(4))
#define aEXECUTE (__constant_cpu_to_le32(8))
#define aDIR (__constant_cpu_to_le32(0x10))
#define aARCH (__constant_cpu_to_le32(0x20))
#define aSHARED (__constant_cpu_to_le32(0x80))
#define aDONTSUBALLOCATE (__constant_cpu_to_le32(1L<<11))
#define aTRANSACTIONAL (__constant_cpu_to_le32(1L<<12))
#define aPURGE (__constant_cpu_to_le32(1L<<16))
#define aRENAMEINHIBIT (__constant_cpu_to_le32(1L<<17))
#define aDELETEINHIBIT (__constant_cpu_to_le32(1L<<18))
#define aDONTCOMPRESS (__constant_cpu_to_le32(1L<<27))

#endif
