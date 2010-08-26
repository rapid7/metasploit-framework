/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _PATHCONF_H_
#define _PATHCONF_H_

/* constants to be used for the 'name' paremeter of pathconf/fpathconf */

#define  _PC_FILESIZEBITS       0x0000
#define  _PC_LINK_MAX           0x0001
#define  _PC_MAX_CANON          0x0002
#define  _PC_MAX_INPUT          0x0003
#define  _PC_NAME_MAX           0x0004
#define  _PC_PATH_MAX           0x0005
#define  _PC_PIPE_BUF           0x0006
#define  _PC_2_SYMLINKS         0x0007
#define  _PC_ALLOC_SIZE_MIN     0x0008
#define  _PC_REC_INCR_XFER_SIZE 0x0009
#define  _PC_REC_MAX_XFER_SIZE  0x000a
#define  _PC_REC_MIN_XFER_SIZE  0x000b
#define  _PC_REC_XFER_ALIGN     0x000c
#define  _PC_SYMLINK_MAX        0x000d
#define  _PC_CHOWN_RESTRICTED   0x000e
#define  _PC_NO_TRUNC           0x000f
#define  _PC_VDISABLE           0x0010
#define  _PC_ASYNC_IO           0x0011
#define  _PC_PRIO_IO            0x0012
#define  _PC_SYNC_IO            0x0013

extern long fpathconf(int fildes, int name);
extern long pathconf(const char *path, int name);

#endif /* _PATHCONF_H_ */

