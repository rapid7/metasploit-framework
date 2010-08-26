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
#include <grp.h>
#include <unistd.h>
#include <stdlib.h>

#define  INIT_GROUPS  2

int
initgroups (const char *user, gid_t group)
{
    gid_t   groups0[ INIT_GROUPS ];
    gid_t*  groups    = groups0;
    int     ret       = -1;
    int     numgroups = INIT_GROUPS;

#if 0 // PKS
    if (getgrouplist(user, group, groups, &numgroups) < 0) {
        groups = malloc(numgroups*sizeof(groups[0]));
        if (groups == NULL)
            return -1;
        if (getgrouplist(user,group,groups,&numgroups) < 0) {
            goto EXIT;
        }
    }
#else 
	// basically what stub does. 
	groups0[0] = group;
	numgroups = 1;
#endif

    ret = setgroups(numgroups, groups);

EXIT:
    if (groups != groups0)
        free(groups);

    return ret;
}
