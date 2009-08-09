#ifndef _METERPRETER_SOURCE_COMMON_CRYPTO_XOR_H
#define _METERPRETER_SOURCE_COMMON_CRYPTO_XOR_H

DWORD xor_populate_handlers(CryptoContext *context);

DWORD xor_process_negotiate_request(CryptoContext *context, 
		struct _Packet *request);
DWORD xor_encrypt(CryptoContext *context, PUCHAR inBuffer, ULONG inBufferLength,
		PUCHAR *outBuffer, PULONG outBufferLength);
DWORD xor_decrypt(CryptoContext *context, PUCHAR inBuffer, ULONG inBufferLength,
		PUCHAR *outBuffer, PULONG outBufferLength);

#endif
