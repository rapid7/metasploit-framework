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
#include <unistd.h>
#include <sys/socket.h>
#include <sys/linux-syscalls.h>

enum
{
    SYS_SOCKET = 1,
    SYS_BIND,
    SYS_CONNECT,
    SYS_LISTEN,
    SYS_ACCEPT,
    SYS_GETSOCKNAME,
    SYS_GETPEERNAME,
    SYS_SOCKETPAIR,
    SYS_SEND,
    SYS_RECV,
    SYS_SENDTO,
    SYS_RECVFROM,
    SYS_SHUTDOWN,
    SYS_SETSOCKOPT,
    SYS_GETSOCKOPT,
    SYS_SENDMSG,
    SYS_RECVMSG
};

#ifndef __NR_socket
int socket(int domain, int type, int protocol)
{
    unsigned long  t[3];

    t[0] = (unsigned long) domain;
    t[1] = (unsigned long) type;
    t[2] = (unsigned long) protocol;

    return (int) __socketcall( SYS_SOCKET, t );
}
#endif /* !__NR_socket */


#ifndef __NR_bind
int bind(int sockfd, const struct sockaddr *my_addr, socklen_t addrlen)
{
    unsigned long  t[3];

    t[0] = (unsigned long) sockfd;
    t[1] = (unsigned long) my_addr;
    t[2] = (unsigned long) addrlen;

    return (int) __socketcall( SYS_BIND, t );
}
#endif  /* !__NR_bind */

#ifndef __NR_connect
int connect(int sockfd, const struct sockaddr *serv_addr, socklen_t  addrlen )
{
    unsigned long  t[3];

    t[0] = (unsigned long) sockfd;
    t[1] = (unsigned long) serv_addr;
    t[2] = (unsigned long) addrlen;

    return (int) __socketcall( SYS_CONNECT, t );
}
#endif /* !__NR_connect */

#ifndef __NR_listen
int listen(int s, int backlog)
{
    unsigned long  t[2];

    t[0] = (unsigned long) s;
    t[1] = (unsigned long) backlog;

    return (int) __socketcall( SYS_LISTEN, t );
}
#endif /* __NR_listen */

#ifndef __NR_accept
int accept(int sock, struct sockaddr *adresse, socklen_t *longueur)
{
    unsigned long  t[3];

    t[0] = (unsigned long) sock;
    t[1] = (unsigned long) adresse;
    t[2] = (unsigned long) longueur;

    return (int) __socketcall( SYS_ACCEPT, t );
}
#endif /* __NR_accept */

#ifndef __NR_getsockname
int getsockname(int s, struct sockaddr * name, socklen_t * namelen )
{
    unsigned long  t[3];

    t[0] = (unsigned long) s;
    t[1] = (unsigned long) name;
    t[2] = (unsigned long) namelen;

    return (int) __socketcall( SYS_GETSOCKNAME, t );
}
#endif /* __NR_getsockname */

#ifndef __NR_getpeername
int getpeername(int s, struct sockaddr *name, socklen_t *namelen)
{
    unsigned long  t[3];

    t[0] = (unsigned long) s;
    t[1] = (unsigned long) name;
    t[2] = (unsigned long) namelen;

    return (int) __socketcall( SYS_GETPEERNAME, t );
}
#endif /* !__NR_getpeername */

#ifndef __NR_socketpair
int socketpair(int d, int type, int protocol, int sv[2])
{
    unsigned long  t[4];

    t[0] = (unsigned long) d;
    t[1] = (unsigned long) type;
    t[2] = (unsigned long) protocol;
    t[3] = (unsigned long) sv;

    return (int) __socketcall( SYS_SOCKETPAIR, t );
}
#endif /* __NR_socketpair */

#ifndef __NR_sendto
ssize_t sendto(int socket, const void *message, size_t length, int flags,
      const struct sockaddr *dest_addr, socklen_t dest_len)
{
    unsigned long  t[6];

    t[0] = (unsigned long) socket;
    t[1] = (unsigned long) message;
    t[2] = (unsigned long) length;
    t[3] = (unsigned long) flags;
    t[4] = (unsigned long) dest_addr;
    t[5] = (unsigned long) dest_len;

   return __socketcall( SYS_SENDTO, t );
}
#endif /* !__NR_sendto */

#ifndef __NR_recvfrom
ssize_t recvfrom(int socket, void *buffer, size_t length, unsigned int flags,
             const struct sockaddr *address, socklen_t *address_len)
{
    unsigned long  t[6];

    t[0] = (unsigned long) socket;
    t[1] = (unsigned long) buffer;
    t[2] = (unsigned long) length;
    t[3] = (unsigned long) flags;
    t[4] = (unsigned long) address;
    t[5] = (unsigned long) address_len;

   return __socketcall( SYS_RECVFROM, t );
}
#endif /* !__NR_recvfrom */

#ifndef __NR_shutdown
int shutdown(int socket, int how)
{
    unsigned long  t[2];

    t[0] = (unsigned long) socket;
    t[1] = (unsigned long) how;

   return (int) __socketcall( SYS_SHUTDOWN, t );
}
#endif /* !__NR_shutdown */

#ifndef __NR_setsockopt
int  setsockopt( int  s, int  level, int  optname, const void*  optval, socklen_t  optlen )
{
    unsigned long  t[5];

    t[0] = (unsigned long) s;
    t[1] = (unsigned long) level;
    t[2] = (unsigned long) optname;
    t[3] = (unsigned long) optval;
    t[4] = (unsigned long) optlen;

   return (int) __socketcall( SYS_SETSOCKOPT, t );
}
#endif /* !__NR_setsockopt */

#ifndef __NR_getsockopt
int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
    unsigned long  t[5];

    t[0] = (unsigned long) s;
    t[1] = (unsigned long) level;
    t[2] = (unsigned long) optname;
    t[3] = (unsigned long) optval;
    t[4] = (unsigned long) optlen;

    return (int) __socketcall( SYS_GETSOCKOPT, t );
}
#endif /* !__NR_getsockopt */

#ifndef __NR_sendmsg
int sendmsg (int socket, const struct msghdr *message, unsigned int flags)
{
    unsigned long  t[3];

    t[0] = (unsigned long) socket;
    t[1] = (unsigned long) message;
    t[2] = (unsigned long) flags;

   return __socketcall( SYS_SENDMSG, t );
}
#endif /* __NR_sendmsg */

#ifndef __NR_recvmsg
int recvmsg(int socket, struct msghdr *message, unsigned int flags)
{
    unsigned long  t[3];

    t[0] = (unsigned long) socket;
    t[1] = (unsigned long) message;
    t[2] = (unsigned long) flags;

   return __socketcall( SYS_RECVMSG, t );
}
#endif /* __NR_recvmsg */

