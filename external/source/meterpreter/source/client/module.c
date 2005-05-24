#include "metcli.h"

typedef struct _ClientModule
{
	LPSTR                name;
	LPSTR                path;
	HMODULE              handle;

	struct _ClientModule *prev;
	struct _ClientModule *next;
} ClientModule;

ClientModule *clientModules = NULL;

/*
 * Load and initialize a client module
 */
DWORD module_load_client(Remote *remote, LPCSTR name, LPCSTR path)
{
	ClientModule *current = NULL;
	DWORD res = ERROR_SUCCESS;
	DWORD (*init)(Remote *remote);

	do
	{
		// Allocate storage for tracking the module
		if (!(current = (ClientModule *)malloc(sizeof(ClientModule))))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Zero the buffer
		memset(current, 0, sizeof(ClientModule));

		current->name = strdup(name);
		current->path = strdup(path);

		// Duplication of name/path failed?
		if ((!current->name) || (!current->path))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Try to load the library from the supplied path
		if (!(current->handle = LoadLibrary(current->path)))
		{
			res = GetLastError();
			break;
		}

		// Try to find the initialization entry point
		if (!(init = (DWORD (*)(Remote *))GetProcAddress(current->handle,
				"InitClientExtension")))
		{
			res = GetLastError();
			break;
		}

		// Initialize the module
		init(remote);

		// Add the new module to the list
		if (clientModules)
			clientModules->prev = current;

		current->next  = clientModules;
		clientModules = current;

	} while (0);

	// Clean up on failure
	if (res != ERROR_SUCCESS)
	{
		if (current)
		{
			if (current->path)
				free(current->path);
			if (current->name)
				free(current->name);

			free(current);
		}
	}

	return res;
}

/*
 * Enumerate the list of modules, returning a pointer to the name at
 * the given index in the output parameter
 */
DWORD module_enumerate_client(DWORD index, LPCSTR *name)
{
	ClientModule *current;
	DWORD cindex = 0;
	DWORD res = ERROR_SUCCESS;

	for (current = clientModules, cindex = 0;
	     cindex < index && current;
	     cindex++, current = current->next);

	if (current)
		*name = current->name;
	else
		res = ERROR_NOT_FOUND;

	return res;
}

/*
 * Unload a previously loaded module of a given name
 */
DWORD module_unload_client(Remote *remote, LPCSTR name)
{
	ClientModule *current = NULL, *prev = NULL;
	DWORD (*deinit)(Remote *remote);
	DWORD res = ERROR_SUCCESS;

	do
	{
		// Try to locate the module
		for (current = clientModules;
		     current;
		     prev = current, current = current->next)
		{
			if (!strcmp(current->name, name))
				break;
		}

		// Not located?
		if (!current)
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		// Remove the module from the list
		if (prev)
			prev->next = current->next;
		else
			clientModules = current->next;

		if (current->next)
			current->next->prev = prev;

		// Call the module's deinitialization routine if it exports one
		if ((deinit = (DWORD (*)(Remote *))GetProcAddress(current->handle,
				"DeinitClientExtension")))
			deinit(remote);

		// Deallocate & unload the module
		FreeLibrary(current->handle);

		free(current->path);
		free(current->name);
		free(current);

	} while (0);

	return res;
}
