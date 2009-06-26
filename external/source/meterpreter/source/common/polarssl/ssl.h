/**
 * \file ssl.h
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
#ifndef POLARSSL_SSL_H
#define POLARSSL_SSL_H

#include <time.h>

#include "polarssl/net.h"
#include "polarssl/dhm.h"
#include "polarssl/rsa.h"
#include "polarssl/md5.h"
#include "polarssl/sha1.h"
#include "polarssl/x509.h"

#define POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE               -0x1000
#define POLARSSL_ERR_SSL_BAD_INPUT_DATA                    -0x1800
#define POLARSSL_ERR_SSL_INVALID_MAC                       -0x2000
#define POLARSSL_ERR_SSL_INVALID_RECORD                    -0x2800
#define POLARSSL_ERR_SSL_INVALID_MODULUS_SIZE              -0x3000
#define POLARSSL_ERR_SSL_UNKNOWN_CIPHER                    -0x3800
#define POLARSSL_ERR_SSL_NO_CIPHER_CHOSEN                  -0x4000
#define POLARSSL_ERR_SSL_NO_SESSION_FOUND                  -0x4800
#define POLARSSL_ERR_SSL_NO_CLIENT_CERTIFICATE             -0x5000
#define POLARSSL_ERR_SSL_CERTIFICATE_TOO_LARGE             -0x5800
#define POLARSSL_ERR_SSL_CERTIFICATE_REQUIRED              -0x6000
#define POLARSSL_ERR_SSL_PRIVATE_KEY_REQUIRED              -0x6800
#define POLARSSL_ERR_SSL_CA_CHAIN_REQUIRED                 -0x7000
#define POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE                -0x7800
#define POLARSSL_ERR_SSL_FATAL_ALERT_MESSAGE               -0x8000
#define POLARSSL_ERR_SSL_PEER_VERIFY_FAILED                -0x8800
#define POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY                 -0x9000
#define POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO               -0x9800
#define POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO               -0xA000
#define POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE                -0xA800
#define POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST        -0xB000
#define POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE        -0xB800
#define POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO_DONE          -0xC000
#define POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE        -0xC800
#define POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY         -0xD000
#define POLARSSL_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC         -0xD800
#define POLARSSL_ERR_SSL_BAD_HS_FINISHED                   -0xE000

/*
 * Various constants
 */
#define SSL_MAJOR_VERSION_3             3
#define SSL_MINOR_VERSION_0             0   /*!< SSL v3.0 */
#define SSL_MINOR_VERSION_1             1   /*!< TLS v1.0 */
#define SSL_MINOR_VERSION_2             2   /*!< TLS v1.1 */

#define SSL_IS_CLIENT                   0
#define SSL_IS_SERVER                   1
#define SSL_COMPRESS_NULL               0

#define SSL_VERIFY_NONE                 0
#define SSL_VERIFY_OPTIONAL             1
#define SSL_VERIFY_REQUIRED             2

#define SSL_MAX_CONTENT_LEN         16384

/*
 * Allow an extra 512 bytes for the record header
 * and encryption overhead (counter + MAC + padding).
 */
#define SSL_BUFFER_LEN (SSL_MAX_CONTENT_LEN + 512)

/*
 * Supported ciphersuites
 */
#define SSL_RSA_RC4_128_MD5              4
#define SSL_RSA_RC4_128_SHA              5
#define SSL_RSA_DES_168_SHA             10
#define SSL_EDH_RSA_DES_168_SHA         22
#define SSL_RSA_AES_128_SHA             47
#define SSL_RSA_AES_256_SHA             53
#define SSL_EDH_RSA_AES_256_SHA         57

#define SSL_RSA_CAMELLIA_128_SHA	0x41
#define SSL_RSA_CAMELLIA_256_SHA	0x84
#define SSL_EDH_RSA_CAMELLIA_256_SHA	0x88

/*
 * Message, alert and handshake types
 */
#define SSL_MSG_CHANGE_CIPHER_SPEC     20
#define SSL_MSG_ALERT                  21
#define SSL_MSG_HANDSHAKE              22
#define SSL_MSG_APPLICATION_DATA       23

#define SSL_ALERT_CLOSE_NOTIFY          0
#define SSL_ALERT_WARNING               1
#define SSL_ALERT_FATAL                 2
#define SSL_ALERT_NO_CERTIFICATE       41

#define SSL_HS_HELLO_REQUEST            0
#define SSL_HS_CLIENT_HELLO             1
#define SSL_HS_SERVER_HELLO             2
#define SSL_HS_CERTIFICATE             11
#define SSL_HS_SERVER_KEY_EXCHANGE     12
#define SSL_HS_CERTIFICATE_REQUEST     13
#define SSL_HS_SERVER_HELLO_DONE       14
#define SSL_HS_CERTIFICATE_VERIFY      15
#define SSL_HS_CLIENT_KEY_EXCHANGE     16
#define SSL_HS_FINISHED                20

/*
 * TLS extensions
 */
#define TLS_EXT_SERVERNAME              0
#define TLS_EXT_SERVERNAME_HOSTNAME     0

/*
 * SSL state machine
 */
typedef enum
{
    SSL_HELLO_REQUEST,
    SSL_CLIENT_HELLO,
    SSL_SERVER_HELLO,
    SSL_SERVER_CERTIFICATE,
    SSL_SERVER_KEY_EXCHANGE,
    SSL_CERTIFICATE_REQUEST,
    SSL_SERVER_HELLO_DONE,
    SSL_CLIENT_CERTIFICATE,
    SSL_CLIENT_KEY_EXCHANGE,
    SSL_CERTIFICATE_VERIFY,
    SSL_CLIENT_CHANGE_CIPHER_SPEC,
    SSL_CLIENT_FINISHED,
    SSL_SERVER_CHANGE_CIPHER_SPEC,
    SSL_SERVER_FINISHED,
    SSL_FLUSH_BUFFERS,
    SSL_HANDSHAKE_OVER
}
ssl_states;

typedef struct _ssl_session ssl_session;
typedef struct _ssl_context ssl_context;

/*
 * This structure is used for session resuming.
 */
struct _ssl_session
{
    time_t start;               /*!< starting time      */
    int cipher;                 /*!< chosen cipher      */
    int length;                 /*!< session id length  */
    unsigned char id[32];       /*!< session identifier */
    unsigned char master[48];   /*!< the master secret  */
    ssl_session *next;          /*!< next session entry */
};

struct _ssl_context
{
    /*
     * Miscellaneous
     */
    int state;                  /*!< SSL handshake: current state     */

    int major_ver;              /*!< equal to  SSL_MAJOR_VERSION_3    */
    int minor_ver;              /*!< either 0 (SSL3) or 1 (TLS1.0)    */

    int max_major_ver;          /*!< max. major version from client   */
    int max_minor_ver;          /*!< max. minor version from client   */

    /*
     * Callbacks (RNG, debug, I/O)
     */
    int  (*f_rng)(void *);
    void (*f_dbg)(void *, int, char *);
    int (*f_recv)(void *, unsigned char *, int);
    int (*f_send)(void *, unsigned char *, int);

    void *p_rng;                /*!< context for the RNG function     */
    void *p_dbg;                /*!< context for the debug function   */
    void *p_recv;               /*!< context for reading operations   */
    void *p_send;               /*!< context for writing operations   */

    /*
     * Session layer
     */
    int resume;                         /*!<  session resuming flag   */
    int timeout;                        /*!<  sess. expiration time   */
    ssl_session *session;               /*!<  current session data    */
    int (*s_get)(ssl_context *);        /*!<  (server) get callback   */
    int (*s_set)(ssl_context *);        /*!<  (server) set callback   */

    /*
     * Record layer (incoming data)
     */
    unsigned char *in_ctr;      /*!< 64-bit incoming message counter  */
    unsigned char *in_hdr;      /*!< 5-byte record header (in_ctr+8)  */
    unsigned char *in_msg;      /*!< the message contents (in_hdr+5)  */
    unsigned char *in_offt;     /*!< read offset in application data  */

    int in_msgtype;             /*!< record header: message type      */
    int in_msglen;              /*!< record header: message length    */
    int in_left;                /*!< amount of data read so far       */

    int in_hslen;               /*!< current handshake message length */
    int nb_zero;                /*!< # of 0-length encrypted messages */

    /*
     * Record layer (outgoing data)
     */
    unsigned char *out_ctr;     /*!< 64-bit outgoing message counter  */
    unsigned char *out_hdr;     /*!< 5-byte record header (out_ctr+8) */
    unsigned char *out_msg;     /*!< the message contents (out_hdr+5) */

    int out_msgtype;            /*!< record header: message type      */
    int out_msglen;             /*!< record header: message length    */
    int out_left;               /*!< amount of data not yet written   */

    /*
     * PKI layer
     */
    rsa_context *rsa_key;               /*!<  own RSA private key     */
    x509_cert *own_cert;                /*!<  own X.509 certificate   */
    x509_cert *ca_chain;                /*!<  own trusted CA chain    */
    x509_crl *ca_crl;                   /*!<  trusted CA CRLs         */
    x509_cert *peer_cert;               /*!<  peer X.509 cert chain   */
    char *peer_cn;                      /*!<  expected peer CN        */

    int endpoint;                       /*!<  0: client, 1: server    */
    int authmode;                       /*!<  verification mode       */
    int client_auth;                    /*!<  flag for client auth.   */
    int verify_result;                  /*!<  verification result     */

    /*
     * Crypto layer
     */
     dhm_context dhm_ctx;               /*!<  DHM key exchange        */
     md5_context fin_md5;               /*!<  Finished MD5 checksum   */
    sha1_context fin_sha1;              /*!<  Finished SHA-1 checksum */

    int do_crypt;                       /*!<  en(de)cryption flag     */
    int *ciphers;                       /*!<  allowed ciphersuites    */
    int pmslen;                         /*!<  premaster length        */
    int keylen;                         /*!<  symmetric key length    */
    int minlen;                         /*!<  min. ciphertext length  */
    int ivlen;                          /*!<  IV length               */
    int maclen;                         /*!<  MAC length              */

    unsigned char randbytes[64];        /*!<  random bytes            */
    unsigned char premaster[256];       /*!<  premaster secret        */

    unsigned char iv_enc[16];           /*!<  IV (encryption)         */
    unsigned char iv_dec[16];           /*!<  IV (decryption)         */

    unsigned char mac_enc[32];          /*!<  MAC (encryption)        */
    unsigned char mac_dec[32];          /*!<  MAC (decryption)        */

    unsigned long ctx_enc[128];         /*!<  encryption context      */
    unsigned long ctx_dec[128];         /*!<  decryption context      */

    /*
     * TLS extensions
     */
    unsigned char *hostname;
    unsigned long  hostname_len;
};

#ifdef __cplusplus
extern "C" {
#endif

extern int ssl_default_ciphers[];

/**
 * \brief          Initialize an SSL context
 *
 * \param ssl      SSL context
 *
 * \return         0 if successful, or 1 if memory allocation failed
 */
int ssl_init( ssl_context *ssl );

/**
 * \brief          Set the current endpoint type
 *
 * \param ssl      SSL context
 * \param endpoint must be SSL_IS_CLIENT or SSL_IS_SERVER
 */
void ssl_set_endpoint( ssl_context *ssl, int endpoint );

/**
 * \brief          Set the certificate verification mode
 *
 * \param ssl      SSL context
 * \param mode     can be:
 *
 *  SSL_VERIFY_NONE:      peer certificate is not checked (default),
 *                        this is insecure and SHOULD be avoided.
 *
 *  SSL_VERIFY_OPTIONAL:  peer certificate is checked, however the
 *                        handshake continues even if verification failed;
 *                        ssl_get_verify_result() can be called after the
 *                        handshake is complete.
 *
 *  SSL_VERIFY_REQUIRED:  peer *must* present a valid certificate,
 *                        handshake is aborted if verification failed.
 */
void ssl_set_authmode( ssl_context *ssl, int authmode );

/**
 * \brief          Set the random number generator callback
 *
 * \param ssl      SSL context
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 */
void ssl_set_rng( ssl_context *ssl,
                  int (*f_rng)(void *),
                  void *p_rng );

/**
 * \brief          Set the debug callback
 *
 * \param ssl      SSL context
 * \param f_dbg    debug function
 * \param p_dbg    debug parameter
 */
void ssl_set_dbg( ssl_context *ssl,
                  void (*f_dbg)(void *, int, char *),
                  void  *p_dbg );

/**
 * \brief          Set the underlying BIO read and write callbacks
 *
 * \param ssl      SSL context
 * \param f_recv   read callback
 * \param p_recv   read parameter
 * \param f_send   write callback
 * \param p_send   write parameter
 */
void ssl_set_bio( ssl_context *ssl,
        int (*f_recv)(void *, unsigned char *, int), void *p_recv,
        int (*f_send)(void *, unsigned char *, int), void *p_send );

/**
 * \brief          Set the session callbacks (server-side only)
 *
 * \param ssl      SSL context
 * \param s_get    session get callback
 * \param s_set    session set callback
 */
void ssl_set_scb( ssl_context *ssl,
                  int (*s_get)(ssl_context *),
                  int (*s_set)(ssl_context *) );

/**
 * \brief          Set the session resuming flag, timeout and data
 *
 * \param ssl      SSL context
 * \param resume   if 0 (default), the session will not be resumed
 * \param timeout  session timeout in seconds, or 0 (no timeout)
 * \param session  session context
 */
void ssl_set_session( ssl_context *ssl, int resume, int timeout,
                      ssl_session *session );

/**
 * \brief          Set the list of allowed ciphersuites
 *
 * \param ssl      SSL context
 * \param ciphers  0-terminated list of allowed ciphers
 */
void ssl_set_ciphers( ssl_context *ssl, int *ciphers );

/**
 * \brief          Set the data required to verify peer certificate
 *
 * \param ssl      SSL context
 * \param ca_chain trusted CA chain
 * \param ca_crl   trusted CA CRLs
 * \param peer_cn  expected peer CommonName (or NULL)
 *
 * \note           TODO: add two more parameters: depth and crl
 */
void ssl_set_ca_chain( ssl_context *ssl, x509_cert *ca_chain,
                       x509_crl *ca_crl, char *peer_cn );

/**
 * \brief          Set own certificate and private key
 *
 * \param ssl      SSL context
 * \param own_cert own public certificate
 * \param rsa_key  own private RSA key
 */
void ssl_set_own_cert( ssl_context *ssl, x509_cert *own_cert,
                       rsa_context *rsa_key );

/**
 * \brief          Set the Diffie-Hellman public P and G values,
 *                 read as hexadecimal strings (server-side only)
 *
 * \param ssl      SSL context
 * \param dhm_P    Diffie-Hellman-Merkle modulus
 * \param dhm_G    Diffie-Hellman-Merkle generator
 *
 * \return         0 if successful
 */
int ssl_set_dh_param( ssl_context *ssl, char *dhm_P, char *dhm_G );

/**
 * \brief          Set hostname for ServerName TLS Extension
 *                 
 *
 * \param ssl      SSL context
 * \param hostname the server hostname
 *
 * \return         0 if successful
 */
int ssl_set_hostname( ssl_context *ssl, char *hostname );

/**
 * \brief          Return the number of data bytes available to read
 *
 * \param ssl      SSL context
 *
 * \return         how many bytes are available in the read buffer
 */
int ssl_get_bytes_avail( ssl_context *ssl );

/**
 * \brief          Return the result of the certificate verification
 *
 * \param ssl      SSL context
 *
 * \return         0 if successful, or a combination of:
 *                      BADCERT_EXPIRED
 *                      BADCERT_REVOKED
 *                      BADCERT_CN_MISMATCH
 *                      BADCERT_NOT_TRUSTED
 */
int ssl_get_verify_result( ssl_context *ssl );

/**
 * \brief          Return the name of the current cipher
 *
 * \param ssl      SSL context
 *
 * \return         a string containing the cipher name
 */
char *ssl_get_cipher( ssl_context *ssl );

/**
 * \brief          Perform the SSL handshake
 *
 * \param ssl      SSL context
 *
 * \return         0 if successful, POLARSSL_ERR_NET_TRY_AGAIN,
 *                 or a specific SSL error code.
 */
int ssl_handshake( ssl_context *ssl );

/**
 * \brief          Read at most 'len' application data bytes
 *
 * \param ssl      SSL context
 * \param buf      buffer that will hold the data
 * \param len      how many bytes must be read
 *
 * \return         This function returns the number of bytes read,
 *                 or a negative error code.
 */
int ssl_read( ssl_context *ssl, unsigned char *buf, int len );

/**
 * \brief          Write exactly 'len' application data bytes
 *
 * \param ssl      SSL context
 * \param buf      buffer holding the data
 * \param len      how many bytes must be written
 *
 * \return         This function returns the number of bytes written,
 *                 or a negative error code.
 *
 * \note           When this function returns POLARSSL_ERR_NET_TRY_AGAIN,
 *                 it must be called later with the *same* arguments,
 *                 until it returns a positive value.
 */
int ssl_write( ssl_context *ssl, unsigned char *buf, int len );

/**
 * \brief          Notify the peer that the connection is being closed
 */
int ssl_close_notify( ssl_context *ssl );

/**
 * \brief          Free an SSL context
 */
void ssl_free( ssl_context *ssl );

/*
 * Internal functions (do not call directly)
 */
int ssl_handshake_client( ssl_context *ssl );
int ssl_handshake_server( ssl_context *ssl );

int ssl_derive_keys( ssl_context *ssl );
void ssl_calc_verify( ssl_context *ssl, unsigned char hash[36] );

int ssl_read_record( ssl_context *ssl );
int ssl_fetch_input( ssl_context *ssl, int nb_want );

int ssl_write_record( ssl_context *ssl );
int ssl_flush_output( ssl_context *ssl );

int ssl_parse_certificate( ssl_context *ssl );
int ssl_write_certificate( ssl_context *ssl );

int ssl_parse_change_cipher_spec( ssl_context *ssl );
int ssl_write_change_cipher_spec( ssl_context *ssl );

int ssl_parse_finished( ssl_context *ssl );
int ssl_write_finished( ssl_context *ssl );

#ifdef __cplusplus
}
#endif

#endif /* ssl.h */
