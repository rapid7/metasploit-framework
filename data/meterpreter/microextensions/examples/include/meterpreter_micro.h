#ifndef METERPRETER_MICRO_H
#define METERPRETER_MICRO_H

#include <winsock2.h>
#include <windows.h>
#include <stdint.h>

#include "common_base.h"
#include "common_channel.h"
#include "common_command_ids.h"
#include "common_scheduler.h"
#include "common_metapi.h"

#define MICRO_EXTENSION_ABI_VERSION 2
#define MICRO_EXTENSION_FLAG_INLINE_HANDLERS 1

typedef DWORD (*MicroChannelOpen)(Remote* remote, Packet* packet, Channel** channel);

typedef struct _MicroChannelProvider
{
	LPCSTR type;
	MicroChannelOpen open;
} MicroChannelProvider;

typedef struct _MicroExtension
{
	DWORD size;
	DWORD abi_version;
	LPCSTR name;
	DWORD command_count;
	Command* commands;
	DWORD flags;
	DWORD channel_provider_count;
	MicroChannelProvider* channel_providers;
} MicroExtension;

typedef const MicroExtension* (*MicroInit)(MetApi* api, Remote* remote);
typedef DWORD (*MicroDeinit)(Remote* remote);

const MicroExtension* micro_init(MetApi* api, Remote* remote);
DWORD micro_deinit(Remote* remote);

#endif
