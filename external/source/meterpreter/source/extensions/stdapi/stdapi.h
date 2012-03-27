#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_H

#include "../../common/common.h"

#ifdef METERPRETER_CLIENT_EXTENSION
	#include "../../client/metcli.h"
#endif

#define TLV_TYPE_EXTENSION_STDAPI 0

#define DELETE_KEY_FLAG_RECURSIVE (1 << 0)

// General
#define TLV_TYPE_HANDLE                \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				600)
#define TLV_TYPE_INHERIT               \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_BOOL,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				601)
#define TLV_TYPE_PROCESS_HANDLE        \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				630)
#define TLV_TYPE_THREAD_HANDLE         \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				631)
#define TLV_TYPE_PRIVILEGE         \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				632)
// Fs
#define TLV_TYPE_DIRECTORY_PATH			MAKE_CUSTOM_TLV( TLV_META_TYPE_STRING,  TLV_TYPE_EXTENSION_STDAPI, 1200 )
#define TLV_TYPE_FILE_NAME				MAKE_CUSTOM_TLV( TLV_META_TYPE_STRING,  TLV_TYPE_EXTENSION_STDAPI, 1201 )
#define TLV_TYPE_FILE_PATH				MAKE_CUSTOM_TLV( TLV_META_TYPE_STRING,  TLV_TYPE_EXTENSION_STDAPI, 1202 )
#define TLV_TYPE_FILE_MODE				MAKE_CUSTOM_TLV( TLV_META_TYPE_STRING,  TLV_TYPE_EXTENSION_STDAPI, 1203 )
#define TLV_TYPE_FILE_SIZE				MAKE_CUSTOM_TLV( TLV_META_TYPE_UINT,    TLV_TYPE_EXTENSION_STDAPI, 1204 )

#define TLV_TYPE_STAT_BUF				MAKE_CUSTOM_TLV( TLV_META_TYPE_COMPLEX, TLV_TYPE_EXTENSION_STDAPI, 1220 )

#define TLV_TYPE_SEARCH_RECURSE			MAKE_CUSTOM_TLV( TLV_META_TYPE_BOOL,    TLV_TYPE_EXTENSION_STDAPI, 1230 )
#define TLV_TYPE_SEARCH_GLOB			MAKE_CUSTOM_TLV( TLV_META_TYPE_STRING,  TLV_TYPE_EXTENSION_STDAPI, 1231 )
#define TLV_TYPE_SEARCH_ROOT			MAKE_CUSTOM_TLV( TLV_META_TYPE_STRING,  TLV_TYPE_EXTENSION_STDAPI, 1232 )
#define TLV_TYPE_SEARCH_RESULTS			MAKE_CUSTOM_TLV( TLV_META_TYPE_GROUP,   TLV_TYPE_EXTENSION_STDAPI, 1233 )

// Process

#define PROCESS_EXECUTE_FLAG_HIDDEN				(1 << 0)
#define PROCESS_EXECUTE_FLAG_CHANNELIZED		(1 << 1)
#define PROCESS_EXECUTE_FLAG_SUSPENDED			(1 << 2)
#define PROCESS_EXECUTE_FLAG_USE_THREAD_TOKEN	(1 << 3)
#define PROCESS_EXECUTE_FLAG_DESKTOP			(1 << 4)
#define PROCESS_EXECUTE_FLAG_SESSION			(1 << 5)

#define TLV_TYPE_BASE_ADDRESS          \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2000)
#define TLV_TYPE_ALLOCATION_TYPE       \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2001)
#define TLV_TYPE_PROTECTION            \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2002)
#define TLV_TYPE_PROCESS_PERMS         \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2003)
#define TLV_TYPE_PROCESS_MEMORY        \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_RAW,         \
				TLV_TYPE_EXTENSION_STDAPI, \
				2004)
#define TLV_TYPE_ALLOC_BASE_ADDRESS    \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2005)
#define TLV_TYPE_MEMORY_STATE          \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2006)
#define TLV_TYPE_MEMORY_TYPE           \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2007)
#define TLV_TYPE_ALLOC_PROTECTION      \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2008)
#define TLV_TYPE_PID                   \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2300)
#define TLV_TYPE_PROCESS_NAME          \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				2301)
#define TLV_TYPE_PROCESS_PATH          \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				2302)
#define TLV_TYPE_PROCESS_GROUP         \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_GROUP,       \
				TLV_TYPE_EXTENSION_STDAPI, \
				2303)
#define TLV_TYPE_PROCESS_FLAGS         \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2304)
#define TLV_TYPE_PROCESS_ARGUMENTS     \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				2305)
#define TLV_TYPE_PROCESS_ARCH     \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				2306)
#define TLV_TYPE_PARENT_PID     \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				2307)
#define TLV_TYPE_PROCESS_SESSION     \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				2308)

#define TLV_TYPE_IMAGE_FILE            \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				2400)
#define TLV_TYPE_IMAGE_FILE_PATH       \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				2401)
#define TLV_TYPE_PROCEDURE_NAME        \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				2402)
#define TLV_TYPE_PROCEDURE_ADDRESS     \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2403)
#define TLV_TYPE_IMAGE_BASE            \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2404)
#define TLV_TYPE_IMAGE_GROUP           \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_GROUP,       \
				TLV_TYPE_EXTENSION_STDAPI, \
				2405)
#define TLV_TYPE_IMAGE_NAME            \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				2406)

#define TLV_TYPE_THREAD_ID             \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2500)
#define TLV_TYPE_THREAD_PERMS          \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2502)
#define TLV_TYPE_EXIT_CODE             \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2510)
#define TLV_TYPE_ENTRY_POINT           \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2511)
#define TLV_TYPE_ENTRY_PARAMETER       \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2512)
#define TLV_TYPE_CREATION_FLAGS        \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2513)

#define TLV_TYPE_REGISTER_NAME         \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				2540)
#define TLV_TYPE_REGISTER_SIZE         \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2541)
#define TLV_TYPE_REGISTER_VALUE_32     \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				2542)
#define TLV_TYPE_REGISTER              \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_GROUP,       \
				TLV_TYPE_EXTENSION_STDAPI, \
				2550)

// Registry
#define TLV_TYPE_HKEY                  \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				1000)
#define TLV_TYPE_ROOT_KEY TLV_TYPE_HKEY
#define TLV_TYPE_BASE_KEY              \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1001)
#define TLV_TYPE_PERMISSION            \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				1002)
#define TLV_TYPE_KEY_NAME              \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1003)

#define TLV_TYPE_VALUE_NAME            \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1010)
#define TLV_TYPE_VALUE_TYPE            \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				1011)
#define TLV_TYPE_VALUE_DATA            \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_RAW,         \
				TLV_TYPE_EXTENSION_STDAPI, \
				1012)
#define TLV_TYPE_TARGET_HOST              \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1013)
// Sys/Config
#define TLV_TYPE_COMPUTER_NAME         \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1040)
#define TLV_TYPE_OS_NAME               \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1041)
#define TLV_TYPE_USER_NAME             \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1042)
#define TLV_TYPE_ARCHITECTURE             \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1043)
#define TLV_TYPE_LANG_SYSTEM             \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1044)
// Net
#define TLV_TYPE_HOST_NAME             \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1400)
#define TLV_TYPE_PORT                  \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				1401)
#define TLV_TYPE_INTERFACE_MTU          \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				1402)
#define TLV_TYPE_INTERFACE_FLAGS          \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				1403)
#define TLV_TYPE_INTERFACE_INDEX          \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				1404)

#define TLV_TYPE_SUBNET                \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_RAW,         \
				TLV_TYPE_EXTENSION_STDAPI, \
				1420)
#define TLV_TYPE_NETMASK               \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_RAW,         \
				TLV_TYPE_EXTENSION_STDAPI, \
				1421)
#define TLV_TYPE_GATEWAY               \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_RAW,         \
				TLV_TYPE_EXTENSION_STDAPI, \
				1422)
#define TLV_TYPE_NETWORK_ROUTE         \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_GROUP,       \
				TLV_TYPE_EXTENSION_STDAPI, \
				1423)
#define TLV_TYPE_IP_PREFIX               \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,         \
				TLV_TYPE_EXTENSION_STDAPI, \
				1424)

#define TLV_TYPE_IP                    \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_RAW,         \
				TLV_TYPE_EXTENSION_STDAPI, \
				1430)
#define TLV_TYPE_MAC_ADDR              \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_RAW,         \
				TLV_TYPE_EXTENSION_STDAPI, \
				1431)
#define TLV_TYPE_MAC_NAME              \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1432)
#define TLV_TYPE_NETWORK_INTERFACE     \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_GROUP,       \
				TLV_TYPE_EXTENSION_STDAPI, \
				1433)
#define TLV_TYPE_IP6_SCOPE     \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_RAW,       \
				TLV_TYPE_EXTENSION_STDAPI, \
				1434)

#define TLV_TYPE_SUBNET_STRING         \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1440)
#define TLV_TYPE_NETMASK_STRING        \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1441)
#define TLV_TYPE_GATEWAY_STRING        \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1442)
#define TLV_TYPE_ROUTE_METRIC         \
                MAKE_CUSTOM_TLV(                 \
                                TLV_META_TYPE_UINT,      \
                                TLV_TYPE_EXTENSION_STDAPI, \
                                1443)

	// Socket
#define TLV_TYPE_PEER_HOST             \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1500)
#define TLV_TYPE_PEER_PORT             \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				1501)
#define TLV_TYPE_LOCAL_HOST            \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				1502)
#define TLV_TYPE_LOCAL_PORT            \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				1503)
#define TLV_TYPE_CONNECT_RETRIES       \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				1504)

#define TLV_TYPE_SHUTDOWN_HOW          \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				1530)

// Ui
#define TLV_TYPE_IDLE_TIME             \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				3000)

#define TLV_TYPE_KEYS_DUMP             \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				3001)

#define TLV_TYPE_DESKTOP_SCREENSHOT					MAKE_CUSTOM_TLV( TLV_META_TYPE_RAW,    TLV_TYPE_EXTENSION_STDAPI, 3002 )
#define TLV_TYPE_DESKTOP_SWITCH						MAKE_CUSTOM_TLV( TLV_META_TYPE_BOOL,   TLV_TYPE_EXTENSION_STDAPI, 3003 )
#define TLV_TYPE_DESKTOP							MAKE_CUSTOM_TLV( TLV_META_TYPE_GROUP,  TLV_TYPE_EXTENSION_STDAPI, 3004 )
#define TLV_TYPE_DESKTOP_SESSION					MAKE_CUSTOM_TLV( TLV_META_TYPE_UINT,   TLV_TYPE_EXTENSION_STDAPI, 3005 )
#define TLV_TYPE_DESKTOP_STATION					MAKE_CUSTOM_TLV( TLV_META_TYPE_STRING, TLV_TYPE_EXTENSION_STDAPI, 3006 )
#define TLV_TYPE_DESKTOP_NAME						MAKE_CUSTOM_TLV( TLV_META_TYPE_STRING, TLV_TYPE_EXTENSION_STDAPI, 3007 )
#define TLV_TYPE_DESKTOP_SCREENSHOT_QUALITY			MAKE_CUSTOM_TLV( TLV_META_TYPE_UINT,   TLV_TYPE_EXTENSION_STDAPI, 3008 )
#define TLV_TYPE_DESKTOP_SCREENSHOT_PE32DLL_LENGTH	MAKE_CUSTOM_TLV( TLV_META_TYPE_UINT,   TLV_TYPE_EXTENSION_STDAPI, 3009 )
#define TLV_TYPE_DESKTOP_SCREENSHOT_PE32DLL_BUFFER	MAKE_CUSTOM_TLV( TLV_META_TYPE_STRING, TLV_TYPE_EXTENSION_STDAPI, 3010 )
#define TLV_TYPE_DESKTOP_SCREENSHOT_PE64DLL_LENGTH	MAKE_CUSTOM_TLV( TLV_META_TYPE_UINT,   TLV_TYPE_EXTENSION_STDAPI, 3011 )
#define TLV_TYPE_DESKTOP_SCREENSHOT_PE64DLL_BUFFER	MAKE_CUSTOM_TLV( TLV_META_TYPE_STRING, TLV_TYPE_EXTENSION_STDAPI, 3012 )

// Event Log
#define TLV_TYPE_EVENT_SOURCENAME      \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				4000)
#define TLV_TYPE_EVENT_HANDLE          \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				4001)
#define TLV_TYPE_EVENT_NUMRECORDS      \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				4002)
#define TLV_TYPE_EVENT_READFLAGS       \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				4003)
#define TLV_TYPE_EVENT_RECORDOFFSET    \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				4004)

#define TLV_TYPE_EVENT_RECORDNUMBER    \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				4006)
#define TLV_TYPE_EVENT_TIMEGENERATED   \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				4007)
#define TLV_TYPE_EVENT_TIMEWRITTEN     \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				4008)
#define TLV_TYPE_EVENT_ID              \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				4009)
/* only a word, but will just put it in a dword */
#define TLV_TYPE_EVENT_TYPE            \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				4010)
/* only a word, but will just put it in a dword */
#define TLV_TYPE_EVENT_CATEGORY        \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				4011)
#define TLV_TYPE_EVENT_STRING          \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_STDAPI, \
				4012)
#define TLV_TYPE_EVENT_DATA            \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_RAW,         \
				TLV_TYPE_EXTENSION_STDAPI, \
				4013)

/* power */
#define TLV_TYPE_POWER_FLAGS           \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				4100)
#define TLV_TYPE_POWER_REASON          \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_UINT,        \
				TLV_TYPE_EXTENSION_STDAPI, \
				4101)

#endif
