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

#ifndef _INCLUDE_SYS_SYSTEM_PROPERTIES_H
#define _INCLUDE_SYS_SYSTEM_PROPERTIES_H

#include <sys/cdefs.h>

__BEGIN_DECLS

typedef struct prop_info prop_info;

#define PROP_NAME_MAX   32
#define PROP_VALUE_MAX  92

/* Look up a system property by name, copying its value and a
** \0 terminator to the provided pointer.  The total bytes
** copied will be no greater than PROP_VALUE_MAX.  Returns
** the string length of the value.  A property that is not
** defined is identical to a property with a length 0 value.
*/
int __system_property_get(const char *name, char *value);

/* Return a pointer to the system property named name, if it
** exists, or NULL if there is no such property.  Use 
** __system_property_read() to obtain the string value from
** the returned prop_info pointer.
**
** It is safe to cache the prop_info pointer to avoid future
** lookups.  These returned pointers will remain valid for
** the lifetime of the system.
*/
const prop_info *__system_property_find(const char *name);

/* Read the value of a system property.  Returns the length
** of the value.  Copies the value and \0 terminator into
** the provided value pointer.  Total length (including
** terminator) will be no greater that PROP_VALUE_MAX.
**
** If name is nonzero, up to PROP_NAME_MAX bytes will be
** copied into the provided name pointer.  The name will
** be \0 terminated.
*/
int __system_property_read(const prop_info *pi, char *name, char *value);

/* Return a prop_info for the nth system property, or NULL if 
** there is no nth property.  Use __system_property_read() to
** read the value of this property.
**
** This method is for inspecting and debugging the property 
** system.  Please use __system_property_find() instead.
**
** Order of results may change from call to call.  This is
** not a bug.
*/ 
const prop_info *__system_property_find_nth(unsigned n);

__END_DECLS

#endif
