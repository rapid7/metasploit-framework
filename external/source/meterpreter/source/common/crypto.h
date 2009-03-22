#ifndef _METERPRETER_SOURCE_COMMON_CRYPTO_H
#define _METERPRETER_SOURCE_COMMON_CRYPTO_H

struct _Remote;
struct _Packet;

typedef struct _CryptoContext
{
	struct _Remote *remote;
	LPVOID         extension;

	struct
	{
		DWORD (*process_negotiate_request)(struct _CryptoContext *ctx, struct _Packet *request);

		DWORD (*encrypt)(struct _CryptoContext *ctx, PUCHAR inBuffer, ULONG inBufferLength,
				PUCHAR *outBuffer, PULONG outBufferLength);
		DWORD (*decrypt)(struct _CryptoContext *ctx, PUCHAR inBuffer, ULONG inBufferLength,
				PUCHAR *outBuffer, PULONG outBufferLength);
	} handlers;

} CryptoContext;

// Individual ciphers
#include "crypto/xor.h"

#endif
