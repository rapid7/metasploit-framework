#ifndef _METERPRETER_LIB_REMOTE_H
#define _METERPRETER_LIB_REMOTE_H

#include "crypto.h"
#include "thread.h"
/*
 * Remote context allocation
 *
 * Wraps the initialized file descriptor for extension purposes
 */
typedef struct _Remote
{
	HMODULE       hMetSrv;
	SOCKET        fd;
	CryptoContext *crypto;
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	LOCK * lock; // lock must be acquired before doing any OpenSSL related action.
} Remote;

Remote *remote_allocate(SOCKET fd);
VOID remote_deallocate(Remote *remote);

VOID remote_set_fd(Remote *remote, SOCKET fd);
SOCKET remote_get_fd(Remote *remote);

DWORD remote_set_cipher(Remote *remote, LPCSTR cipher, 
		struct _Packet *initializer);
CryptoContext *remote_get_cipher(Remote *remote);

#endif
