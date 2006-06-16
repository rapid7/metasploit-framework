#include "common.h"

/*
 * Parse an argument vector by a parameter format specifier
 */
DWORD args_parse(UINT argc, CHAR **argv, PCHAR params, 
		ArgumentContext *ctx)
{
	DWORD index = 0;

	if (!ctx->currentIndex)
		ctx->currentIndex = 1;

	index = ctx->currentIndex;

	// We've hit the end, return out.
	if (index >= argc)
		return ERROR_NOT_FOUND;

	// Is this a toggled parameter?
	if (argv[index][0] == '-')
	{
		PCHAR currentParam = params;
		BOOL hasParam = FALSE;

		// Check to see if this argument expects a parameter
		while (*currentParam)
		{
			if (*currentParam == argv[index][1])
			{
				hasParam = (*(currentParam + 1) == ':') ? TRUE : FALSE;
				break;
			}

			currentParam++;
		}

		// If this param requires an argument yet is not given one, fail.
		if ((hasParam) &&
		    (index + 1 >= argc))
			return ERROR_INVALID_PARAMETER;

		ctx->argument = (hasParam) ? argv[index+1] : NULL;
		ctx->toggle   = argv[index][1]; 

		// Skip past the parameter.
		if (hasParam)
			++index;
	}
	else
		ctx->toggle = 0;

	// Update the index
	ctx->currentIndex = ++index;

	return ERROR_SUCCESS;
}
