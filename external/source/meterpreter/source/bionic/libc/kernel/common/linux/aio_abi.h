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
#ifndef __LINUX__AIO_ABI_H
#define __LINUX__AIO_ABI_H

#include <asm/byteorder.h>

typedef unsigned long aio_context_t;

enum {
 IOCB_CMD_PREAD = 0,
 IOCB_CMD_PWRITE = 1,
 IOCB_CMD_FSYNC = 2,
 IOCB_CMD_FDSYNC = 3,

 IOCB_CMD_NOOP = 6,
};

struct io_event {
 __u64 data;
 __u64 obj;
 __s64 res;
 __s64 res2;
};

#ifdef __LITTLE_ENDIAN
#define PADDED(x,y) x, y
#elif defined(__BIG_ENDIAN)
#define PADDED(x,y) y, x
#else
#error edit for your odd byteorder.
#endif

struct iocb {

 __u64 aio_data;
 __u32 PADDED(aio_key, aio_reserved1);

 __u16 aio_lio_opcode;
 __s16 aio_reqprio;
 __u32 aio_fildes;

 __u64 aio_buf;
 __u64 aio_nbytes;
 __s64 aio_offset;

 __u64 aio_reserved2;
 __u64 aio_reserved3;
};

#undef IFBIG
#undef IFLITTLE

#endif

