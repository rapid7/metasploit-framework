/**
 * \file des.h
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
#ifndef POLARSSL_DES_H
#define POLARSSL_DES_H

#define DES_ENCRYPT     1
#define DES_DECRYPT     0

/**
 * \brief          DES context structure
 */
typedef struct
{
    int mode;                   /*!<  encrypt/decrypt   */
    unsigned long sk[32];       /*!<  DES subkeys       */
}
des_context;

/**
 * \brief          Triple-DES context structure
 */
typedef struct
{
    int mode;                   /*!<  encrypt/decrypt   */
    unsigned long sk[96];       /*!<  3DES subkeys      */
}
des3_context;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          DES key schedule (56-bit, encryption)
 *
 * \param ctx      DES context to be initialized
 * \param key      8-byte secret key
 */
void des_setkey_enc( des_context *ctx, unsigned char key[8] );

/**
 * \brief          DES key schedule (56-bit, decryption)
 *
 * \param ctx      DES context to be initialized
 * \param key      8-byte secret key
 */
void des_setkey_dec( des_context *ctx, unsigned char key[8] );

/**
 * \brief          Triple-DES key schedule (112-bit, encryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      16-byte secret key
 */
void des3_set2key_enc( des3_context *ctx, unsigned char key[16] );

/**
 * \brief          Triple-DES key schedule (112-bit, decryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      16-byte secret key
 */
void des3_set2key_dec( des3_context *ctx, unsigned char key[16] );

/**
 * \brief          Triple-DES key schedule (168-bit, encryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      24-byte secret key
 */
void des3_set3key_enc( des3_context *ctx, unsigned char key[24] );

/**
 * \brief          Triple-DES key schedule (168-bit, decryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      24-byte secret key
 */
void des3_set3key_dec( des3_context *ctx, unsigned char key[24] );

/**
 * \brief          DES-ECB block encryption/decryption
 *
 * \param ctx      DES context
 * \param input    64-bit input block
 * \param output   64-bit output block
 */
void des_crypt_ecb( des_context *ctx,
                    unsigned char input[8],
                    unsigned char output[8] );

/**
 * \brief          DES-CBC buffer encryption/decryption
 *
 * \param ctx      DES context
 * \param mode     DES_ENCRYPT or DES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 */
void des_crypt_cbc( des_context *ctx,
                    int mode,
                    int length,
                    unsigned char iv[8],
                    unsigned char *input,
                    unsigned char *output );

/**
 * \brief          3DES-ECB block encryption/decryption
 *
 * \param ctx      3DES context
 * \param input    64-bit input block
 * \param output   64-bit output block
 */
void des3_crypt_ecb( des3_context *ctx,
                     unsigned char input[8],
                     unsigned char output[8] );

/**
 * \brief          3DES-CBC buffer encryption/decryption
 *
 * \param ctx      3DES context
 * \param mode     DES_ENCRYPT or DES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 */
void des3_crypt_cbc( des3_context *ctx,
                     int mode,
                     int length,
                     unsigned char iv[8],
                     unsigned char *input,
                     unsigned char *output );

/*
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int des_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* des.h */
