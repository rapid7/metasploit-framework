#include "common.h"

#define TLV_TYPE_XOR_KEY         \
		MAKE_CUSTOM_TLV(           \
				TLV_META_TYPE_UINT,  \
				0,                   \
				1)

DWORD xor_crypt(CryptoContext *context, PUCHAR inBuffer, ULONG inBufferLength,
		PUCHAR *outBuffer, PULONG outBufferLength);

/*
 * Populates the crypto context's handlers for XOR
 */
DWORD xor_populate_handlers(CryptoContext *context)
{
	context->extension                          = NULL;
	context->handlers.process_negotiate_request = xor_process_negotiate_request;
	context->handlers.encrypt                   = xor_encrypt;
	context->handlers.decrypt                   = xor_decrypt;

	return ERROR_SUCCESS;
}

/*
 * Processes a negotiate request that has been sent from the remote endpoint
 */
DWORD xor_process_negotiate_request(CryptoContext *context, 
		Packet *request)
{
	Tlv cipherParameters, xorKey;
	DWORD res = ERROR_INVALID_PARAMETER;

	memset(&xorKey, 0, sizeof(xorKey));

	// If valid parameters were supplied
	if ((packet_get_tlv(request, TLV_TYPE_CIPHER_PARAMETERS, 
			&cipherParameters) == ERROR_SUCCESS) &&
	    (packet_get_tlv_group_entry(request, &cipherParameters, 
			TLV_TYPE_XOR_KEY, &xorKey) == ERROR_SUCCESS) &&
	    (xorKey.header.length >= sizeof(DWORD)))
	{
		// Set the XOR key to what has been supplied to us
		context->extension = (LPVOID)ntohl(*(LPDWORD)xorKey.buffer);

		res = ERROR_SUCCESS;
	}

	return res;
}

/*
 * Encrypts the supplied buffer
 */
DWORD xor_encrypt(CryptoContext *context, PUCHAR inBuffer, ULONG inBufferLength,
		PUCHAR *outBuffer, PULONG outBufferLength)
{
	return xor_crypt(context, inBuffer, inBufferLength, outBuffer,
			outBufferLength);
}

/*
 * Decrypts the supplied buffer
 */
DWORD xor_decrypt(CryptoContext *context, PUCHAR inBuffer, ULONG inBufferLength,
		PUCHAR *outBuffer, PULONG outBufferLength)
{
	return xor_crypt(context, inBuffer, inBufferLength, outBuffer,
			outBufferLength);
}

/*
 * Performs an XOR operation on every 4 byte block of the supplied buffer
 */
DWORD xor_crypt(CryptoContext *context, PUCHAR inBuffer, ULONG inBufferLength,
		PUCHAR *outBuffer, PULONG outBufferLength)
{
	DWORD newLength = inBufferLength, remainder = inBufferLength % 4, offset = 0;
	PUCHAR newBuffer = NULL;
	LPDWORD currentIn, currentOut;
	DWORD res = ERROR_SUCCESS;
	DWORD key = (DWORD)context->extension;

	if (remainder)
		newLength += 4 - remainder;

	do
	{
		// No memory?
		if (!(newBuffer = (PUCHAR)malloc(newLength)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// We assume that though the input buffer may not align on a 4 byte
		// boundary, its allocated unit should.  Given that, we don't care what
		// the overflow bytes are.  Anyone see anything wrong w/ this?
		for (currentIn = (LPDWORD)inBuffer, currentOut = (LPDWORD)newBuffer, offset = 0;
		     offset < newLength;
		     currentIn++, currentOut++, offset += 4)
			*currentOut = *currentIn ^ key;

	} while (0);

	// Did we fail or what?
	if (res != ERROR_SUCCESS)
	{
		if (newBuffer)
			free(newBuffer);

		newBuffer = NULL;
	}

	// Populate our out pointers
	if (outBuffer)
		*outBuffer = newBuffer;
	if (outBufferLength)
		*outBufferLength = newLength;

	return res;
}
