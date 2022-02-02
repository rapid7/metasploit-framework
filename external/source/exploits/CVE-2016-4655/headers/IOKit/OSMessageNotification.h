/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */

#ifndef	__OS_OSMESSAGENOTIFICATION_H
#define __OS_OSMESSAGENOTIFICATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <mach/mach_types.h>
#include <device/device_types.h>
#include <IOKit/IOReturn.h>

enum {
    kFirstIOKitNotificationType 		= 100,
    kIOServicePublishNotificationType 		= 100,
    kIOServiceMatchedNotificationType		= 101,
    kIOServiceTerminatedNotificationType	= 102,
    kIOAsyncCompletionNotificationType		= 150,
    kIOServiceMessageNotificationType		= 160,
    kLastIOKitNotificationType 			= 199,

    // reserved bits
    kIOKitNoticationTypeMask                    = 0x00000FFF,
    kIOKitNoticationTypeSizeAdjShift            = 30,
    kIOKitNoticationMsgSizeMask                 = 3,
};

enum {
    kOSNotificationMessageID		= 53,
    kOSAsyncCompleteMessageID		= 57,
    kMaxAsyncArgs			= 16
};

enum {
    kIOAsyncReservedIndex 	= 0,
    kIOAsyncReservedCount,

    kIOAsyncCalloutFuncIndex 	= kIOAsyncReservedCount,
    kIOAsyncCalloutRefconIndex,
    kIOAsyncCalloutCount,

    kIOMatchingCalloutFuncIndex	= kIOAsyncReservedCount,
    kIOMatchingCalloutRefconIndex,
    kIOMatchingCalloutCount,
    
    kIOInterestCalloutFuncIndex	= kIOAsyncReservedCount,
    kIOInterestCalloutRefconIndex,
    kIOInterestCalloutServiceIndex,
    kIOInterestCalloutCount
};



// --------------
enum {
    kOSAsyncRef64Count	= 8,
    kOSAsyncRef64Size 	= kOSAsyncRef64Count * ((int) sizeof(io_user_reference_t))
};
typedef io_user_reference_t OSAsyncReference64[kOSAsyncRef64Count];

struct OSNotificationHeader64 {
    mach_msg_size_t	size;		/* content size */
    natural_t		type;
    OSAsyncReference64	reference;

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
    unsigned char	content[];
#else
    unsigned char	content[0];
#endif
};

#pragma pack(4)
struct IOServiceInterestContent64 {
    natural_t		messageType;
    io_user_reference_t	messageArgument[1];
};
#pragma pack()
// --------------

#if !KERNEL_USER32

enum {
    kOSAsyncRefCount	= 8,
    kOSAsyncRefSize 	= 32
};
typedef natural_t OSAsyncReference[kOSAsyncRefCount];

struct OSNotificationHeader {
    mach_msg_size_t	size;		/* content size */
    natural_t		type;
    OSAsyncReference	reference;

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
    unsigned char	content[];
#else
    unsigned char	content[0];
#endif
};

#pragma pack(4)
struct IOServiceInterestContent {
    natural_t	messageType;
    void *	messageArgument[1];
};
#pragma pack()

#endif /* KERNEL_USER32  */

struct IOAsyncCompletionContent {
    IOReturn result;
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
    void * args[] __attribute__ ((packed));
#else
    void * args[0] __attribute__ ((packed));
#endif
};

#ifndef __cplusplus
typedef struct OSNotificationHeader OSNotificationHeader;
typedef struct IOServiceInterestContent IOServiceInterestContent;
typedef struct IOAsyncCompletionContent IOAsyncCompletionContent;
#endif

#ifdef __cplusplus
}
#endif

#endif /*  __OS_OSMESSAGENOTIFICATION_H */

