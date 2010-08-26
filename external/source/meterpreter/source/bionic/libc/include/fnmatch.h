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
#ifndef _FNMATCH_H
#define _FNMATCH_H

#include <sys/cdefs.h>

__BEGIN_DECLS

#define FNM_NOMATCH      1     /* Match failed. */
#define FNM_NOSYS        2     /* Function not supported (unused). */

#define FNM_NOESCAPE     0x01        /* Disable backslash escaping. */
#define FNM_PATHNAME     0x02        /* Slash must be matched by slash. */
#define FNM_PERIOD       0x04        /* Period must be matched by period. */
#define FNM_LEADING_DIR  0x08        /* Ignore /<tail> after Imatch. */
#define FNM_CASEFOLD     0x10        /* Case insensitive search. */

#define FNM_IGNORECASE   FNM_CASEFOLD
#define FNM_FILE_NAME    FNM_PATHNAME

extern int  fnmatch(const char *pattern, const char *string, int flags);

__END_DECLS

#endif /* _FNMATCH_H */

