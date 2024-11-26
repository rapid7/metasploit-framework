/*
 *  aix-power.h
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

#ifndef AIX_POWER_H
#define AIX_POWER_H

#define __CAL 2047

#if defined(AIX614)
#define __NR_execve      = 7
#define __NR_getpeername = 211
#define __NR_accept      = 237
#define __NR_listen      = 240
#define __NR_bind        = 242
#define __NR_socket      = 243
#define __NR_connect     = 244
#define __NR_close       = 278
#define __NR_kfcntl      = 658
#endif

#if defined(AIX613)
#define __NR_execve      = 7
#define __NR_getpeername = 205
#define __NR_accept      = 232
#define __NR_listen      = 235
#define __NR_bind        = 237
#define __NR_socket      = 238
#define __NR_connect     = 239
#define __NR_close       = 272
#define __NR_kfcntl      = 644
#endif

#if defined(AIX612)
#define __NR_execve      = 7
#define __NR_getpeername = 205
#define __NR_accept      = 232
#define __NR_listen      = 235
#define __NR_bind        = 237
#define __NR_socket      = 238
#define __NR_connect     = 239
#define __NR_close       = 272
#define __NR_kfcntl      = 635
#endif

#if defined(AIX611)
#define __NR_execve      = 7
#define __NR_getpeername = 202
#define __NR_accept      = 229
#define __NR_listen      = 232
#define __NR_bind        = 234
#define __NR_socket      = 235
#define __NR_connect     = 236
#define __NR_close       = 269
#define __NR_kfcntl      = 614
#endif

#if defined(AIX610)
#define __NR_execve      = 6
#define __NR_getpeername = 203
#define __NR_accept      = 229
#define __NR_listen      = 232
#define __NR_bind        = 234
#define __NR_socket      = 235
#define __NR_connect     = 236
#define __NR_close       = 269
#define __NR_kfcntl      = 617
#endif

#if defined(AIX5310) || defined(AIX539) || defined(AIX538) || defined(AIX537)
#define __NR_execve      = 6
#define __NR_getpeername = 198
#define __NR_accept      = 214
#define __NR_listen      = 215
#define __NR_bind        = 216
#define __NR_socket      = 217
#define __NR_connect     = 218
#define __NR_close       = 245
#define __NR_kfcntl      = 493
#endif

#define __NC_execve      -(__CAL - __NR_execve)
#define __NC_getpeername -(__CAL - __NR_getpeername)
#define __NC_accept      -(__CAL - __NR_accept)
#define __NC_listen      -(__CAL - __NR_listen)
#define __NC_bind        -(__CAL - __NR_bind)
#define __NC_socket      -(__CAL - __NR_socket)
#define __NC_connect     -(__CAL - __NR_connect)
#define __NC_close       -(__CAL - __NR_close)
#define __NC_kfcntl      -(__CAL - __NR_kfcntl)

#endif

