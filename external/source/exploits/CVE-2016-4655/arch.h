/*
 * arch.h - Code to deal with different architectures.
 *          Taken from kern-utils
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016-2017 Siguza
 */

#ifndef ARCH_H
#define ARCH_H

#include <mach-o/loader.h>      // mach_header, mach_header_64, segment_command, segment_command_64
#include <Foundation/Foundation.h> // NSLog

#define IMAGE_OFFSET 0x2000
#define MACH_TYPE CPU_TYPE_ARM64
#define ADDR "%016lx"
#define SIZE "%lu"
#define MACH_HEADER_MAGIC MH_MAGIC_64
#define MACH_LC_SEGMENT LC_SEGMENT_64
#define MACH_LC_SEGMENT_NAME "LC_SEGMENT_64"
#define KERNEL_SPACE 0x8000000000000000
typedef struct mach_header_64 mach_hdr_t;
typedef struct segment_command_64 mach_seg_t;
typedef struct section_64 mach_sec_t;
typedef struct load_command mach_lc_t;

#define LOG(str, args...) \
do \
{ \
    NSLog(@"" str "\n", ##args); \
} while(0)

#endif
