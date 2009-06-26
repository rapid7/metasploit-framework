/**
 * \file debug.h
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
#ifndef SSL_DEBUG_H
#define SSL_DEBUG_H

#include "polarssl/config.h"
#include "polarssl/ssl.h"

#if defined(POLARSSL_DEBUG_MSG)

#define SSL_DEBUG_MSG( level, args )                    \
    debug_print_msg( ssl, level, __FILE__, __LINE__, debug_fmt args );

#define SSL_DEBUG_RET( level, text, ret )                \
    debug_print_ret( ssl, level, __FILE__, __LINE__, text, ret );

#define SSL_DEBUG_BUF( level, text, buf, len )           \
    debug_print_buf( ssl, level, __FILE__, __LINE__, text, buf, len );

#define SSL_DEBUG_MPI( level, text, X )                  \
    debug_print_mpi( ssl, level, __FILE__, __LINE__, text, X );

#define SSL_DEBUG_CRT( level, text, crt )                \
    debug_print_crt( ssl, level, __FILE__, __LINE__, text, crt );

#else

#define SSL_DEBUG_MSG( level, args )            do { } while( 0 )
#define SSL_DEBUG_RET( level, text, ret )       do { } while( 0 )
#define SSL_DEBUG_BUF( level, text, buf, len )  do { } while( 0 )
#define SSL_DEBUG_MPI( level, text, X )         do { } while( 0 )
#define SSL_DEBUG_CRT( level, text, crt )       do { } while( 0 )

#endif

#ifdef __cplusplus
extern "C" {
#endif

char *debug_fmt( const char *format, ... );

void debug_print_msg( ssl_context *ssl, int level,
                      char *file, int line, char *text );

void debug_print_ret( ssl_context *ssl, int level,
                      char *file, int line, char *text, int ret );

void debug_print_buf( ssl_context *ssl, int level,
                      char *file, int line, char *text,
                      unsigned char *buf, int len );

void debug_print_mpi( ssl_context *ssl, int level,
                      char *file, int line, char *text, mpi *X );

void debug_print_crt( ssl_context *ssl, int level,
                      char *file, int line, char *text, x509_cert *crt );

#ifdef __cplusplus
}
#endif

#endif /* debug.h */
