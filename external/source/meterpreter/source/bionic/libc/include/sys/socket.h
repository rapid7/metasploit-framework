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
#ifndef _SYS_SOCKET_H_
#define _SYS_SOCKET_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <linux/socket.h>

__BEGIN_DECLS

#define SOCK_STREAM      1
#define SOCK_DGRAM       2
#define SOCK_RAW         3
#define SOCK_RDM         4
#define SOCK_SEQPACKET   5
#define SOCK_PACKET      10

#ifdef __i386__
# define __socketcall extern __attribute__((__cdecl__))
#else
# define __socketcall extern
#endif

/* BIONIC: second argument to shutdown() */
enum {
    SHUT_RD = 0,        /* no more receptions */
#define SHUT_RD         SHUT_RD
    SHUT_WR,            /* no more transmissions */
#define SHUT_WR         SHUT_WR
    SHUT_RDWR           /* no more receptions or transmissions */
#define SHUT_RDWR       SHUT_RDWR
};


typedef int socklen_t;

__socketcall int socket(int, int, int);
__socketcall int bind(int, const struct sockaddr *, int);
__socketcall int connect(int, const struct sockaddr *, socklen_t);
__socketcall int listen(int, int);
__socketcall int accept(int, struct sockaddr *, socklen_t *);
__socketcall int getsockname(int, struct sockaddr *, socklen_t *);
__socketcall int getpeername(int, struct sockaddr *, socklen_t *);
__socketcall int socketpair(int, int, int, int *);
__socketcall int shutdown(int, int);
__socketcall int setsockopt(int, int, int, const void *, socklen_t);
__socketcall int getsockopt(int, int, int, void *, socklen_t *);
__socketcall int sendmsg(int, const struct msghdr *, unsigned int);
__socketcall int recvmsg(int, struct msghdr *, unsigned int);

extern  ssize_t  send(int, const void *, size_t, unsigned int);
extern  ssize_t  recv(int, void *, size_t, unsigned int);

__socketcall ssize_t sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
__socketcall ssize_t recvfrom(int, void *, size_t, unsigned int, const struct sockaddr *, socklen_t *);

#undef __socketcall

__END_DECLS

#endif /* _SYS_SOCKET_H */
