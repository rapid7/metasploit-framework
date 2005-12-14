/*
 * This module implements privilege escalation features. 
 */
#include "precomp.h"

Command customCommands[] =
{
	// Priv
	{ "priv_passwd_get_sam_hashes",
	  { request_passwd_get_sam_hashes,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Fs
	{ "priv_fs_get_file_mace",
	  { request_fs_get_file_mace,                          { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "priv_fs_set_file_mace",
	  { request_fs_set_file_mace,                          { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "priv_fs_set_file_mace_from_file",
	  { request_fs_set_file_mace_from_file,                { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "priv_fs_blank_file_mace",
	  { request_fs_blank_file_mace,                        { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "priv_fs_blank_directory_mace",
	  { request_fs_blank_directory_mace,                   { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER                      },
	  { EMPTY_DISPATCH_HANDLER                      },
	},
};

/*
 * Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	DWORD index;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_register(&customCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	DWORD index;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_deregister(&customCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * DLL entry point for persisting the module handle
 */
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
{
	return TRUE;
}
