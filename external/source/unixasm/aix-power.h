/*
 *  $Id: aix-power.h 40 2008-11-17 02:45:30Z ramon $
 *
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

#define __CAL 511

#ifdef V410
#define __NR_execve      3
#define __NR_getpeername 67
#define __NR_accept      83
#define __NR_listen      85
#define __NR_bind        86
#define __NR_socket      87
#define __NR_connect     88
#define __NR_close       94
#define __NR_kfcntl      214
#endif

#ifdef V420
#define __NR_execve      2
#define __NR_getpeername 72
#define __NR_accept      88
#define __NR_listen      89
#define __NR_bind        90
#define __NR_socket      91
#define __NR_connect     92
#define __NR_close       98
#define __NR_kfcntl      231
#endif

#ifdef V430
#define __NR_execve      4
#define __NR_getpeername 85
#define __NR_accept      101
#define __NR_listen      103
#define __NR_bind        104
#define __NR_socket      105
#define __NR_connect     106
#define __NR_close       113
#define __NR_kfcntl      252
#endif

#ifdef V433
#define __NR_execve      3
#define __NR_getpeername 101
#define __NR_accept      117
#define __NR_listen      118
#define __NR_bind        119
#define __NR_socket      120
#define __NR_connect     121
#define __NR_close       130
#define __NR_kfcntl      271
#endif

#ifdef V530
#define __NR_execve      5
#define __NR_getpeername 122
#define __NR_accept      138
#define __NR_listen      139
#define __NR_bind        140
#define __NR_socket      141
#define __NR_connect     142
#define __NR_close       160
#define __NR_kfcntl      322
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
