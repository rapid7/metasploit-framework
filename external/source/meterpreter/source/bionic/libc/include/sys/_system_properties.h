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

#ifndef _INCLUDE_SYS__SYSTEM_PROPERTIES_H
#define _INCLUDE_SYS__SYSTEM_PROPERTIES_H

#ifndef _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#error you should #include <sys/system_properties.h> instead
#else
#include <sys/system_properties.h>

typedef struct prop_area prop_area;
typedef struct prop_msg prop_msg;

#define PROP_AREA_MAGIC   0x504f5250
#define PROP_AREA_VERSION 0x45434f76

#define PROP_SERVICE_NAME "property_service"

/* #define PROP_MAX_ENTRIES 247 */
/* 247 -> 32620 bytes (<32768) */

#define TOC_NAME_LEN(toc)       ((toc) >> 24)
#define TOC_TO_INFO(area, toc)  ((prop_info*) (((char*) area) + ((toc) & 0xFFFFFF)))

struct prop_area {
    unsigned volatile count;
    unsigned volatile serial;
    unsigned magic;
    unsigned version;
    unsigned reserved[4];
    unsigned toc[1];
};

#define SERIAL_VALUE_LEN(serial) ((serial) >> 24)
#define SERIAL_DIRTY(serial) ((serial) & 1)

struct prop_info {
    char name[PROP_NAME_MAX];
    unsigned volatile serial;
    char value[PROP_VALUE_MAX];
};

struct prop_msg 
{
    unsigned cmd;
    char name[PROP_NAME_MAX];
    char value[PROP_VALUE_MAX];
};

#define PROP_MSG_SETPROP 1
    
/*
** Rules:
**
** - there is only one writer, but many readers
** - prop_area.count will never decrease in value
** - once allocated, a prop_info's name will not change
** - once allocated, a prop_info's offset will not change
** - reading a value requires the following steps
**   1. serial = pi->serial
**   2. if SERIAL_DIRTY(serial), wait*, then goto 1
**   3. memcpy(local, pi->value, SERIAL_VALUE_LEN(serial) + 1)
**   4. if pi->serial != serial, goto 2
**
** - writing a value requires the following steps
**   1. pi->serial = pi->serial | 1
**   2. memcpy(pi->value, local_value, value_len)
**   3. pi->serial = (value_len << 24) | ((pi->serial + 1) & 0xffffff)
**
** Improvements:
** - maintain the toc sorted by pi->name to allow lookup
**   by binary search
**
*/

#define PROP_PATH_RAMDISK_DEFAULT  "/default.prop"
#define PROP_PATH_SYSTEM_BUILD     "/system/build.prop"
#define PROP_PATH_SYSTEM_DEFAULT   "/system/default.prop"
#define PROP_PATH_LOCAL_OVERRIDE   "/data/local.prop"

#endif
#endif
