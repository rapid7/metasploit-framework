/*
 * This client feature extension provides the following:
 *
 *
 */
#include "../boiler.h"

extern DWORD cmd_boiler(Remote *remote, UINT argc, CHAR **argv);

ConsoleCommand commonCommands[] =
{
	{ "", NULL,         "",   1 },
	{ "boiler",      cmd_boiler,   "Boiler plate.",                                       0 },

	// Terminator
	{ NULL,          NULL,         NULL,                                                  0 },
};


/*
 * Register extensions
 */
DWORD __declspec(dllexport) InitClientExtension()
{
	DWORD index;

	for (index = 0;
	     commonCommands[index].name;
	     index++)
		console_register_command(&commonCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deregister extensions
 */
DWORD __declspec(dllexport) DeinitClientExtension()
{
	DWORD index;

	for (index = 0;
	     commonCommands[index].name;
	     index++)
		console_deregister_command(&commonCommands[index]);

	return ERROR_SUCCESS;
}
