/**
 * \file md2.h
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
#ifndef POLARSSL_MD2_H
#define POLARSSL_MD2_H

/**
 * \brief          MD2 context structure
 */
typedef struct
{
    unsigned char cksum[16];    /*!< checksum of the data block */
    unsigned char state[48];    /*!< intermediate digest state  */
    unsigned char buffer[16];   /*!< data block being processed */

    unsigned char ipad[64];     /*!< HMAC: inner padding        */
    unsigned char opad[64];     /*!< HMAC: outer padding        */
    int left;                   /*!< amount of data in buffer   */
}
md2_context;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          MD2 context setup
 *
 * \param ctx      context to be initialized
 */
void md2_starts( md2_context *ctx );

/**
 * \brief          MD2 process buffer
 *
 * \param ctx      MD2 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void md2_update( md2_context *ctx, unsigned char *input, int ilen );

/**
 * \brief          MD2 final digest
 *
 * \param ctx      MD2 context
 * \param output   MD2 checksum result
 */
void md2_finish( md2_context *ctx, unsigned char output[16] );

/**
 * \brief          Output = MD2( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   MD2 checksum result
 */
void md2( unsigned char *input, int ilen, unsigned char output[16] );

/**
 * \brief          Output = MD2( file contents )
 *
 * \param path     input file name
 * \param output   MD2 checksum result
 *
 * \return         0 if successful, 1 if fopen failed,
 *                 or 2 if fread failed
 */
int md2_file( char *path, unsigned char output[16] );

/**
 * \brief          MD2 HMAC context setup
 *
 * \param ctx      HMAC context to be initialized
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 */
void md2_hmac_starts( md2_context *ctx, unsigned char *key, int keylen );

/**
 * \brief          MD2 HMAC process buffer
 *
 * \param ctx      HMAC context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void md2_hmac_update( md2_context *ctx, unsigned char *input, int ilen );

/**
 * \brief          MD2 HMAC final digest
 *
 * \param ctx      HMAC context
 * \param output   MD2 HMAC checksum result
 */
void md2_hmac_finish( md2_context *ctx, unsigned char output[16] );

/**
 * \brief          Output = HMAC-MD2( hmac key, input buffer )
 *
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   HMAC-MD2 result
 */
void md2_hmac( unsigned char *key, int keylen,
               unsigned char *input, int ilen,
               unsigned char output[16] );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int md2_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* md2.h */
