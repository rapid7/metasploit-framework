/*-
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)pwd.h	8.2 (Berkeley) 1/21/94
 */

/*-
 * Portions Copyright(C) 1995, Jason Downs.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _PWD_H_
#define _PWD_H_

#include <sys/cdefs.h>
#include <sys/types.h>

#define _PATH_PASSWD        "/etc/passwd"
#define _PATH_MASTERPASSWD  "/etc/master.passwd"
#define _PATH_MASTERPASSWD_LOCK "/etc/ptmp"

#define _PATH_PASSWD_CONF   "/etc/passwd.conf"
#define _PATH_PASSWDCONF    _PATH_PASSWD_CONF   /* XXX: compat */
#define _PATH_USERMGMT_CONF "/etc/usermgmt.conf"

#define _PATH_MP_DB     "/etc/pwd.db"
#define _PATH_SMP_DB        "/etc/spwd.db"

#define _PATH_PWD_MKDB      "/usr/sbin/pwd_mkdb"

#define _PW_KEYBYNAME       '1' /* stored by name */
#define _PW_KEYBYNUM        '2' /* stored by entry in the "file" */
#define _PW_KEYBYUID        '3' /* stored by uid */

#define _PASSWORD_EFMT1     '_' /* extended DES encryption format */
#define _PASSWORD_NONDES    '$' /* non-DES encryption formats */

#define _PASSWORD_LEN       128 /* max length, not counting NUL */

#define _PASSWORD_NOUID     0x01    /* flag for no specified uid. */
#define _PASSWORD_NOGID     0x02    /* flag for no specified gid. */
#define _PASSWORD_NOCHG     0x04    /* flag for no specified change. */
#define _PASSWORD_NOEXP     0x08    /* flag for no specified expire. */

#define _PASSWORD_OLDFMT    0x10    /* flag to expect an old style entry */
#define _PASSWORD_NOWARN    0x20    /* no warnings for bad entries */

#define _PASSWORD_WARNDAYS  14  /* days to warn about expiry */
#define _PASSWORD_CHGNOW    -1  /* special day to force password change at next login */

struct passwd
{
    char* pw_name;
    char* pw_passwd;
    uid_t pw_uid;
    gid_t pw_gid;
    char* pw_dir;
    char* pw_shell;
};

__BEGIN_DECLS

struct passwd* getpwnam(const char*);
struct passwd* getpwuid(uid_t);

int getpwnam_r(const char*, struct passwd*, char*, size_t, struct passwd**);
int getpwuid_r(uid_t, struct passwd*, char*, size_t, struct passwd**);

void endpwent(void);
struct passwd* getpwent(void);
int setpwent(void);

__END_DECLS

#endif
