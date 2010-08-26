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
#ifndef _ZLIB_H
#define _ZLIB_H

#include <linux/zconf.h>

struct internal_state;

typedef struct z_stream_s {
 Byte *next_in;
 uInt avail_in;
 uLong total_in;

 Byte *next_out;
 uInt avail_out;
 uLong total_out;

 char *msg;
 struct internal_state *state;

 void *workspace;

 int data_type;
 uLong adler;
 uLong reserved;
} z_stream;

typedef z_stream *z_streamp;

#define Z_NO_FLUSH 0
#define Z_PARTIAL_FLUSH 1  
#define Z_PACKET_FLUSH 2
#define Z_SYNC_FLUSH 3
#define Z_FULL_FLUSH 4
#define Z_FINISH 5
#define Z_BLOCK 6  

#define Z_OK 0
#define Z_STREAM_END 1
#define Z_NEED_DICT 2
#define Z_ERRNO (-1)
#define Z_STREAM_ERROR (-2)
#define Z_DATA_ERROR (-3)
#define Z_MEM_ERROR (-4)
#define Z_BUF_ERROR (-5)
#define Z_VERSION_ERROR (-6)

#define Z_NO_COMPRESSION 0
#define Z_BEST_SPEED 1
#define Z_BEST_COMPRESSION 9
#define Z_DEFAULT_COMPRESSION (-1)

#define Z_FILTERED 1
#define Z_HUFFMAN_ONLY 2
#define Z_DEFAULT_STRATEGY 0

#define Z_BINARY 0
#define Z_ASCII 1
#define Z_UNKNOWN 2

#define Z_DEFLATED 8

#define zlib_deflateInit(strm, level)   zlib_deflateInit2((strm), (level), Z_DEFLATED, MAX_WBITS,   DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY)
#define zlib_inflateInit(strm)   zlib_inflateInit2((strm), DEF_WBITS)

#if !defined(_Z_UTIL_H) && !defined(NO_DUMMY_DECL)
 struct internal_state {int dummy;};
#endif

#endif
