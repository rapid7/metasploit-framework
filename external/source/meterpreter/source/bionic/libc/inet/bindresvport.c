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
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#define START_PORT	600
#define END_PORT	IPPORT_RESERVED
#define NUM_PORTS	(END_PORT - START_PORT)

int bindresvport(int sd, struct sockaddr_in *sin)
{
    static short        port;
    struct sockaddr_in  sin0;
    int                 nn, ret;

    if (sin == NULL) {
        sin = &sin0;
        memset( sin, 0, sizeof *sin );
        sin->sin_family = AF_INET;
    } else if (sin->sin_family != AF_INET) {
        errno = EPFNOSUPPORT;
        return -1;
    }

    if (port == 0) {
        port = START_PORT + (getpid() % NUM_PORTS);
    }

    for (nn = NUM_PORTS; nn > 0; nn--, port++) 
    {
        if (port == END_PORT)
            port = START_PORT;

        sin->sin_port = htons(port);
        do {
            ret = bind(sd, (struct sockaddr*)sin, sizeof(*sin));
        } while (ret < 0 && errno == EINTR);

        if (!ret)
            break;
    }
    return ret;
}
