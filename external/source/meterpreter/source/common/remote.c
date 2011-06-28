#include "common.h"

/*
 * Instantiate a remote context from a file descriptor
 */
Remote *remote_allocate(SOCKET fd)
{
	Remote *remote = NULL;

	// Allocate the remote context
	if ((remote = (Remote *)malloc(sizeof(Remote))))
	{
		memset(remote, 0, sizeof(Remote));

		// Set the file descriptor
		remote->fd = fd;

		remote->lock = lock_create();


		// If we failed to create the lock we must fail to create the remote
		// as we wont be able to synchronize communication correctly.
		if( remote->lock == NULL )
		{
			remote_deallocate( remote );
			return NULL;
		}
	}

	return remote;
}

/*
 * Deallocate a remote context
 */
VOID remote_deallocate( Remote * remote )
{
	if( remote->fd )
		closesocket( remote->fd );
	
	if( remote->lock )
		lock_destroy( remote->lock );

	if ( remote->uri )
		free( remote->uri);

	// Wipe our structure from memory
	memset(remote, 0, sizeof(Remote));

	free(remote);
}

/*
 * Override a previously set file descriptor
 */
VOID remote_set_fd(Remote *remote, SOCKET fd)
{
	remote->fd = fd;
}

/*
 * Get the remote context's file descriptor
 */
SOCKET remote_get_fd(Remote *remote)
{
	return remote->fd;
}

/*
 * Initializes a given cipher as instructed to by the remote endpoint
 */
DWORD remote_set_cipher(Remote *remote, LPCSTR cipher, Packet *initializer)
{
	DWORD res = ERROR_SUCCESS;

	if (remote->crypto)
		free(remote->crypto);

	do
	{
		// Allocate storage for the crypto context
		if (!(remote->crypto = (CryptoContext *)malloc(sizeof(CryptoContext))))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		memset(remote->crypto, 0, sizeof(CryptoContext));

		// Set the remote pointer on the crypto context
		remote->crypto->remote = remote;

		// Populate handlers according to what cipher was selected
		if (!strcmp(cipher, "xor"))
			res = xor_populate_handlers(remote->crypto);
		else
			res = ERROR_NOT_FOUND;

		// If we got a context and it wants to process the request, do it.
		if ((res == ERROR_SUCCESS) &&
		    (remote->crypto->handlers.process_negotiate_request))
			res = remote->crypto->handlers.process_negotiate_request(
					remote->crypto, initializer);

	} while (0);

	// If we fail, destroy the crypto context should it have been allocated.
	if (res != ERROR_SUCCESS)
	{
		if (remote->crypto)
			free(remote->crypto);

		remote->crypto = NULL;
	}

	return res;
}

/*
 * Returns a pointer to the remote endpoint's crypto context
 */
CryptoContext *remote_get_cipher(Remote *remote)
{
	return remote->crypto;
}
