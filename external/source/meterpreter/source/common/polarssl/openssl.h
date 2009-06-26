/**
 * \file openssl.h
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
/*
 * OpenSSL wrapper contributed by David Barett
 */
#ifndef POLARSSL_OPENSSL_H
#define POLARSSL_OPENSSL_H

#include "polarssl/aes.h"
#include "polarssl/md5.h"
#include "polarssl/rsa.h"
#include "polarssl/sha1.h"

#define AES_SIZE                16
#define AES_BLOCK_SIZE          16
#define AES_KEY                 aes_context
#define MD5_CTX                 md5_context
#define SHA_CTX                 sha1_context

#define SHA1_Init( CTX ) \
        sha1_starts( (CTX) )
#define SHA1_Update(  CTX, BUF, LEN ) \
        sha1_update( (CTX), (unsigned char *)(BUF), (LEN) )
#define SHA1_Final( OUT, CTX ) \
        sha1_finish( (CTX), (OUT) )

#define MD5_Init( CTX ) \
        md5_starts( (CTX) )
#define MD5_Update( CTX, BUF, LEN ) \
        md5_update( (CTX), (unsigned char *)(BUF), (LEN) )
#define MD5_Final( OUT, CTX ) \
        md5_finish( (CTX), (OUT) )

#define AES_set_encrypt_key( KEY, KEYSIZE, CTX ) \
        aes_setkey_enc( (CTX), (KEY), (KEYSIZE) )
#define AES_set_decrypt_key( KEY, KEYSIZE, CTX ) \
        aes_setkey_dec( (CTX), (KEY), (KEYSIZE) )
#define AES_cbc_encrypt( INPUT, OUTPUT, LEN, CTX, IV, MODE ) \
        aes_crypt_cbc( (CTX), (MODE), (LEN), (IV), (INPUT), (OUTPUT) )

/*
 * RSA stuff follows. TODO: needs cleanup
 */
inline int __RSA_Passthrough( void *output, void *input, int size )
{
    memcpy( output, input, size );
    return size;
}

inline rsa_context* d2i_RSA_PUBKEY( void *ignore, unsigned char **bufptr,
                                    int len )
{
    unsigned char *buffer = *(unsigned char **) bufptr;
    rsa_context *rsa;
    
    /*
     * Not a general-purpose parser: only parses public key from *exactly*
     *   openssl genrsa -out privkey.pem 512 (or 1024)
     *   openssl rsa -in privkey.pem -out privatekey.der -outform der
     *   openssl rsa -in privkey.pem -out pubkey.der -outform der -pubout
     *
     * TODO: make a general-purpose parse
     */
    if( ignore != 0 || ( len != 94 && len != 162 ) )
        return( 0 );

    rsa = (rsa_context *) malloc( sizeof( rsa_rsa ) );
    if( rsa == NULL )
        return( 0 );

    memset( rsa, 0, sizeof( rsa_context ) );

    if( ( len ==  94 && 
          mpi_read_binary( &rsa->N, &buffer[ 25],  64 ) == 0 &&
          mpi_read_binary( &rsa->E, &buffer[ 91],   3 ) == 0 ) ||
        ( len == 162 &&
          mpi_read_binary( &rsa->N, &buffer[ 29], 128 ) == 0 ) &&
          mpi_read_binary( &rsa->E, &buffer[159],   3 ) == 0 )
    {
        /*
         * key read successfully
         */
        rsa->len = ( mpi_msb( &rsa->N ) + 7 ) >> 3;
        return( rsa );
    }
    else
    {
        memset( rsa, 0, sizeof( rsa_context ) );
        free( rsa );
        return( 0 );
    }
}

#define RSA                     rsa_context
#define RSA_PKCS1_PADDING       1 /* ignored; always encrypt with this */
#define RSA_size( CTX )         (CTX)->len
#define RSA_free( CTX )         rsa_free( CTX )
#define ERR_get_error( )        "ERR_get_error() not supported"
#define RSA_blinding_off( IGNORE )

#define d2i_RSAPrivateKey( a, b, c ) new rsa_context /* TODO: C++ bleh */

inline int RSA_public_decrypt ( int size, unsigned char* input, unsigned char* output, RSA* key, int ignore ) { int outsize=size; if( !rsa_pkcs1_decrypt( key, RSA_PUBLIC,  &outsize, input, output ) ) return outsize; else return -1; }
inline int RSA_private_decrypt( int size, unsigned char* input, unsigned char* output, RSA* key, int ignore ) { int outsize=size; if( !rsa_pkcs1_decrypt( key, RSA_PRIVATE, &outsize, input, output ) ) return outsize; else return -1; }
inline int RSA_public_encrypt ( int size, unsigned char* input, unsigned char* output, RSA* key, int ignore ) { if( !rsa_pkcs1_encrypt( key, RSA_PUBLIC,  size, input, output ) ) return RSA_size(key); else return -1; }
inline int RSA_private_encrypt( int size, unsigned char* input, unsigned char* output, RSA* key, int ignore ) { if( !rsa_pkcs1_encrypt( key, RSA_PRIVATE, size, input, output ) ) return RSA_size(key); else return -1; }

#ifdef __cplusplus
}
#endif

#endif /* openssl.h */
