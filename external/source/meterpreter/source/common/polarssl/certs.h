/**
 * \file certs.h
 *
 *  Based on XySSL: Copyright (C) 2006-2008  Christophe Devine
 *
 *  Copyright (C) 2009  Paul Bakker <polarssl_maintainer at polarssl dot org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_CERTS_H
#define POLARSSL_CERTS_H

#ifdef __cplusplus
extern "C" {
#endif

extern char test_ca_crt[];
extern char test_ca_key[];
extern char test_ca_pwd[];
extern char test_srv_crt[];
extern char test_srv_key[];
extern char test_cli_crt[];
extern char test_cli_key[];
extern char xyssl_ca_crt[];

#ifdef __cplusplus
}
#endif

#endif /* certs.h */
