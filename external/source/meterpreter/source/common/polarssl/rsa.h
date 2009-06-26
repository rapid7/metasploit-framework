/**
 * \file rsa.h
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
#ifndef POLARSSL_RSA_H
#define POLARSSL_RSA_H

#include "polarssl/bignum.h"

#define POLARSSL_ERR_RSA_BAD_INPUT_DATA                    -0x0400
#define POLARSSL_ERR_RSA_INVALID_PADDING                   -0x0410
#define POLARSSL_ERR_RSA_KEY_GEN_FAILED                    -0x0420
#define POLARSSL_ERR_RSA_KEY_CHECK_FAILED                  -0x0430
#define POLARSSL_ERR_RSA_PUBLIC_FAILED                     -0x0440
#define POLARSSL_ERR_RSA_PRIVATE_FAILED                    -0x0450
#define POLARSSL_ERR_RSA_VERIFY_FAILED                     -0x0460
#define POLARSSL_ERR_RSA_OUTPUT_TO_LARGE                   -0x0470

/*
 * PKCS#1 constants
 */
#define RSA_RAW         0

#define SIG_RSA_MD2	2
#define SIG_RSA_MD4	3
#define SIG_RSA_MD5	4
#define SIG_RSA_SHA1	5
#define SIG_RSA_SHA224	14
#define SIG_RSA_SHA256	11
#define	SIG_RSA_SHA384	12
#define SIG_RSA_SHA512	13

#define RSA_PUBLIC      0
#define RSA_PRIVATE     1

#define RSA_PKCS_V15    0
#define RSA_PKCS_V21    1

#define RSA_SIGN        1
#define RSA_CRYPT       2

#define ASN1_STR_CONSTRUCTED_SEQUENCE	"\x30"
#define ASN1_STR_NULL			"\x05"
#define ASN1_STR_OID			"\x06"
#define ASN1_STR_OCTET_STRING		"\x04"

#define OID_DIGEST_ALG_MDX	"\x2A\x86\x48\x86\xF7\x0D\x02\x00"
#define OID_HASH_ALG_SHA1	"\x2b\x0e\x03\x02\x1a"
#define OID_HASH_ALG_SHA2X	"\x60\x86\x48\x01\x65\x03\x04\x02\x00"

#define OID_ISO_MEMBER_BODIES	"\x2a"
#define OID_ISO_IDENTIFIED_ORG	"\x2b"

/*
 * ISO Member bodies OID parts
 */
#define OID_COUNTRY_US		"\x86\x48"
#define OID_RSA_DATA_SECURITY	"\x86\xf7\x0d"

/*
 * ISO Identified organization OID parts
 */
#define OID_OIW_SECSIG_SHA1	"\x0e\x03\x02\x1a"

/*
 * DigestInfo ::= SEQUENCE {
 *   digestAlgorithm DigestAlgorithmIdentifier,
 *   digest Digest }
 *
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * Digest ::= OCTET STRING
 */
#define ASN1_HASH_MDX					\
(							\
    ASN1_STR_CONSTRUCTED_SEQUENCE "\x20"		\
      ASN1_STR_CONSTRUCTED_SEQUENCE "\x0C"		\
        ASN1_STR_OID "\x08"				\
	  OID_DIGEST_ALG_MDX				\
	ASN1_STR_NULL "\x00"				\
      ASN1_STR_OCTET_STRING "\x10"			\
)

#define ASN1_HASH_SHA1					\
    ASN1_STR_CONSTRUCTED_SEQUENCE "\x21"		\
      ASN1_STR_CONSTRUCTED_SEQUENCE "\x09"		\
        ASN1_STR_OID "\x05"				\
	  OID_HASH_ALG_SHA1				\
        ASN1_STR_NULL "\x00"				\
      ASN1_STR_OCTET_STRING "\x14"

#define ASN1_HASH_SHA2X					\
    ASN1_STR_CONSTRUCTED_SEQUENCE "\x11"		\
      ASN1_STR_CONSTRUCTED_SEQUENCE "\x0d"		\
        ASN1_STR_OID "\x09"				\
	  OID_HASH_ALG_SHA2X				\
        ASN1_STR_NULL "\x00"				\
      ASN1_STR_OCTET_STRING "\x00"

/**
 * \brief          RSA context structure
 */
typedef struct
{
    int ver;                    /*!<  always 0          */
    int len;                    /*!<  size(N) in chars  */

    mpi N;                      /*!<  public modulus    */
    mpi E;                      /*!<  public exponent   */

    mpi D;                      /*!<  private exponent  */
    mpi P;                      /*!<  1st prime factor  */
    mpi Q;                      /*!<  2nd prime factor  */
    mpi DP;                     /*!<  D % (P - 1)       */
    mpi DQ;                     /*!<  D % (Q - 1)       */
    mpi QP;                     /*!<  1 / (Q % P)       */

    mpi RN;                     /*!<  cached R^2 mod N  */
    mpi RP;                     /*!<  cached R^2 mod P  */
    mpi RQ;                     /*!<  cached R^2 mod Q  */

    int padding;                /*!<  1.5 or OAEP/PSS   */
    int hash_id;                /*!<  hash identifier   */
    int (*f_rng)(void *);       /*!<  RNG function      */
    void *p_rng;                /*!<  RNG parameter     */
}
rsa_context;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Initialize an RSA context
 *
 * \param ctx      RSA context to be initialized
 * \param padding  RSA_PKCS_V15 or RSA_PKCS_V21
 * \param hash_id  RSA_PKCS_V21 hash identifier
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \note           The hash_id parameter is actually ignored
 *                 when using RSA_PKCS_V15 padding.
 *
 * \note           Currently (xyssl-0.8), RSA_PKCS_V21 padding
 *                 is not supported.
 */
void rsa_init( rsa_context *ctx,
               int padding,
               int hash_id,
               int (*f_rng)(void *),
               void *p_rng );

/**
 * \brief          Generate an RSA keypair
 *
 * \param ctx      RSA context that will hold the key
 * \param nbits    size of the public key in bits
 * \param exponent public exponent (e.g., 65537)
 *
 * \note           rsa_init() must be called beforehand to setup
 *                 the RSA context (especially f_rng and p_rng).
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 */
int rsa_gen_key( rsa_context *ctx, int nbits, int exponent );

/**
 * \brief          Check a public RSA key
 *
 * \param ctx      RSA context to be checked
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 */
int rsa_check_pubkey( rsa_context *ctx );

/**
 * \brief          Check a private RSA key
 *
 * \param ctx      RSA context to be checked
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 */
int rsa_check_privkey( rsa_context *ctx );

/**
 * \brief          Do an RSA public key operation
 *
 * \param ctx      RSA context
 * \param input    input buffer
 * \param output   output buffer
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           This function does NOT take care of message
 *                 padding. Also, be sure to set input[0] = 0 or assure that
 *                 input is smaller than N.
 *
 * \note           The input and output buffers must be large
 *                 enough (eg. 128 bytes if RSA-1024 is used).
 */
int rsa_public( rsa_context *ctx,
                unsigned char *input,
                unsigned char *output );

/**
 * \brief          Do an RSA private key operation
 *
 * \param ctx      RSA context
 * \param input    input buffer
 * \param output   output buffer
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The input and output buffers must be large
 *                 enough (eg. 128 bytes if RSA-1024 is used).
 */
int rsa_private( rsa_context *ctx,
                 unsigned char *input,
                 unsigned char *output );

/**
 * \brief          Add the message padding, then do an RSA operation
 *
 * \param ctx      RSA context
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param ilen     contains the plaintext length
 * \param input    buffer holding the data to be encrypted
 * \param output   buffer that will hold the ciphertext
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int rsa_pkcs1_encrypt( rsa_context *ctx,
                       int mode, int  ilen,
                       unsigned char *input,
                       unsigned char *output );

/**
 * \brief          Do an RSA operation, then remove the message padding
 *
 * \param ctx      RSA context
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param input    buffer holding the encrypted data
 * \param output   buffer that will hold the plaintext
 * \param olen     will contain the plaintext length
 * \param output_max_len	maximum length of the output buffer
 *
 * \return         0 if successful, or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used) otherwise
 *                 an error is thrown.
 */
int rsa_pkcs1_decrypt( rsa_context *ctx,
                       int mode, int *olen,
                       unsigned char *input,
                       unsigned char *output,
		       int output_max_len);

/**
 * \brief          Do a private RSA to sign a message digest
 *
 * \param ctx      RSA context
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param hash_id  RSA_RAW, SIG_RSA_MD{2,4,5} or SIG_RSA_SHA{1,224,256,384,512}
 * \param hashlen  message digest length (for RSA_RAW only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer that will hold the ciphertext
 *
 * \return         0 if the signing operation was successful,
 *                 or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int rsa_pkcs1_sign( rsa_context *ctx,
                    int mode,
                    int hash_id,
                    int hashlen,
                    unsigned char *hash,
                    unsigned char *sig );

/**
 * \brief          Do a public RSA and check the message digest
 *
 * \param ctx      points to an RSA public key
 * \param mode     RSA_PUBLIC or RSA_PRIVATE
 * \param hash_id  RSA_RAW, RSA_MD{2,4,5} or RSA_SHA{1,256}
 * \param hashlen  message digest length (for RSA_RAW only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer holding the ciphertext
 *
 * \return         0 if the verify operation was successful,
 *                 or an POLARSSL_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int rsa_pkcs1_verify( rsa_context *ctx,
                      int mode,
                      int hash_id,
                      int hashlen,
                      unsigned char *hash,
                      unsigned char *sig );

/**
 * \brief          Free the components of an RSA key
 */
void rsa_free( rsa_context *ctx );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int rsa_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* rsa.h */
