/*****************************************************************************

$Id$

File:     ssl.h
Date:     30Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/


#ifndef __SslBox__H_
#define __SslBox__H_




#ifdef WITH_SSL

/******************
class SslContext_t
******************/

class SslContext_t
{
	public:
		SslContext_t (bool is_server, const std::string &privkeyfile, const std::string &certchainfile, const std::string &cipherlist, const std::string &ecdh_curve, const std::string &dhparam, int ssl_version);
		virtual ~SslContext_t();

	private:
		static bool bLibraryInitialized;

	private:
		bool bIsServer;
		SSL_CTX *pCtx;

		EVP_PKEY *PrivateKey;
		X509 *Certificate;

	friend class SslBox_t;
};


/**************
class SslBox_t
**************/

#define SSLBOX_INPUT_CHUNKSIZE 2019
#define SSLBOX_OUTPUT_CHUNKSIZE 2048
#define SSLBOX_WRITE_BUFFER_SIZE 8192 // (SSLBOX_OUTPUT_CHUNKSIZE * 4)

class SslBox_t
{
	public:
		SslBox_t (bool is_server, const std::string &privkeyfile, const std::string &certchainfile, bool verify_peer, bool fail_if_no_peer_cert, const std::string &snihostname, const std::string &cipherlist, const std::string &ecdh_curve, const std::string &dhparam, int ssl_version, const uintptr_t binding);
		virtual ~SslBox_t();

		int PutPlaintext (const char*, int);
		int GetPlaintext (char*, int);

		bool PutCiphertext (const char*, int);
		bool CanGetCiphertext();
		int GetCiphertext (char*, int);
		bool IsHandshakeCompleted() {return bHandshakeCompleted;}

		X509 *GetPeerCert();
		int GetCipherBits();
		const char *GetCipherName();
		const char *GetCipherProtocol();
		const char *GetSNIHostname();

		void Shutdown();

	protected:
		SslContext_t *Context;

		bool bIsServer;
		bool bHandshakeCompleted;
		bool bVerifyPeer;
		bool bFailIfNoPeerCert;
		SSL *pSSL;
		BIO *pbioRead;
		BIO *pbioWrite;

		PageList OutboundQ;
};

extern "C" int ssl_verify_wrapper(int, X509_STORE_CTX*);

#endif // WITH_SSL


#endif // __SslBox__H_

