/*
 *  $Id: linux-power.h 40 2008-11-17 02:45:30Z ramon $
 *
 *  linux-power.h
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

#ifndef LINUX_POWER_H
#define LINUX_POWER_H

#define __CAL 511

#define __NR_exit        1
#define __NR_execve      11
#define __NR_setuid      23
#define __NR_dup2        63
#define __NR_setreuid    70
#define __NR_setresuid   164
#define __NR_socketcall  102

#define __NC_exit        -(__CAL - __NR_exit)
#define __NC_execve      -(__CAL - __NR_execve)
#define __NC_setuid      -(__CAL - __NR_setuid)
#define __NC_dup2        -(__CAL - __NR_dup2)
#define __NC_setreuid    -(__CAL - __NR_setreuid)
#define __NC_setresuid   -(__CAL - __NR_setresuid)
#define __NC_socketcall  -(__CAL - __NR_socketcall)

#define __SC_socket      1
#define __SC_bind        2
#define __SC_connect     3
#define __SC_listen      4
#define __SC_accept      5
#define __SC_getpeername 7

#define __NC_socket      -(__CAL - __SC_socket)
#define __NC_bind        -(__CAL - __SC_bind)
#define __NC_connect     -(__CAL - __SC_connect)
#define __NC_listen      -(__CAL - __SC_listen)
#define __NC_accept      -(__CAL - __SC_accept)
#define __NC_getpeername -(__CAL - __SC_getpeername)

#endif
