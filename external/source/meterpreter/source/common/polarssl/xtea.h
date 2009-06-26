/**
 * \file xtea.h
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
#ifndef POLARSSL_XTEA_H
#define POLARSSL_XTEA_H

#include <inttypes.h>

#define XTEA_ENCRYPT     1
#define XTEA_DECRYPT     0


/**
 * \brief          XTEA context structure
 */
typedef struct
{
    uint32_t k[4];       /*!< key */
}
xtea_context;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          XTEA key schedule
 *
 * \param ctx      XTEA context to be initialized
 * \param key      the secret key
 */
void xtea_setup( xtea_context *ctx, unsigned char key[16] );

/**
 * \brief          XTEA cipher function
 *
 * \param ctx      XTEA context
 * \param mode     XTEA_ENCRYPT or XTEA_DECRYPT
 * \param input    8-byte input block
 * \param output   8-byte output block
 */
void xtea_crypt( xtea_context *ctx,
		 int mode,
		 unsigned char input[8],
		 unsigned char output[8] );

/*
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int xtea_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* xtea.h */
