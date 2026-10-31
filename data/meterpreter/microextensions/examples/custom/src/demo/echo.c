#include "micro_runtime.h"

#define COMMAND_ID_MICRO_ECHO 18001

static MetApi* echo_api = NULL;

static DWORD echo_handler(Remote* remote, Packet* packet)
{
	Packet* response = echo_api->packet.create_response(packet);
	const char* text = echo_api->packet.get_tlv_value_string(packet, TLV_TYPE_STRING);
	DWORD result = text == NULL ? ERROR_INVALID_PARAMETER : ERROR_SUCCESS;

	if (response != NULL)
	{
		if (result == ERROR_SUCCESS)
		{
			echo_api->packet.add_tlv_string(response, TLV_TYPE_STRING, text);
		}
		result = echo_api->packet.transmit_response(result, remote, response);
	}
	else
	{
		result = ERROR_NOT_ENOUGH_MEMORY;
	}

	return result;
}

static BOOL echo_inline(Remote* remote, Packet* packet, DWORD* result)
{
	*result = echo_handler(remote, packet);
	return TRUE;
}

static Command echo_commands[] =
{
	COMMAND_INLINE_REQ(COMMAND_ID_MICRO_ECHO, echo_inline),
	COMMAND_TERMINATOR
};

static MicroExtension echo_extension =
{
	sizeof(MicroExtension),
	MICRO_EXTENSION_ABI_VERSION,
	"micro-yaml-echo",
	1,
	echo_commands,
	MICRO_EXTENSION_FLAG_INLINE_HANDLERS
};

const MicroExtension* micro_init(MetApi* api, Remote* remote)
{
	(void)remote;
	if (api == NULL || api->packet.create_response == NULL || api->packet.get_tlv_value_string == NULL || api->packet.add_tlv_string == NULL || api->packet.transmit_response == NULL)
	{
		return NULL;
	}

	echo_api = api;
	return &echo_extension;
}

DWORD micro_deinit(Remote* remote)
{
	(void)remote;
	echo_api = NULL;
	return ERROR_SUCCESS;
}
