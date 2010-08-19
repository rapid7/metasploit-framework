#include "metsrv.h"

#ifdef _WIN32
// see ReflectiveLoader.c...
extern HINSTANCE hAppInstance;
#endif

/**************************
 * Core dispatch routines *
 **************************/

LIST * extension_list = NULL;

// Dispatch table
Command custom_commands[] = 
{
	{
	  "core_loadlib", 
	  { request_core_loadlib,              { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                      },
	},

	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER                      },
	  { EMPTY_DISPATCH_HANDLER                      },
	},
};

/*
 * Registers custom command handlers
 */
VOID register_dispatch_routines()
{
	DWORD index;

	extension_list = list_create();

	for( index=0 ; custom_commands[index].method ; index++ )
		command_register( &custom_commands[index] );
}

/*
 * Deregisters previously registered custom commands and loaded extensions.
 */
VOID deregister_dispatch_routines( Remote * remote )
{
	DWORD index;

	while( TRUE )
	{
		EXTENSION * extension = list_pop( extension_list );
		if( !extension )
			break;

		extension->deinit( remote );

		free( extension );
	}

	for( index=0 ; custom_commands[index].method ; index++ )
		command_deregister( &custom_commands[index] );

	list_destroy( extension_list );
}
