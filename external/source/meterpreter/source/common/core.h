#ifndef _METERPRETER_CORE_H
#define _METERPRETER_CORE_H

#include "linkage.h"
#include "remote.h"

/*
 * Enumerations for TLVs and packets
 */
#define MAKE_TLV(name, meta, actual) TLV_TYPE_ ## name = actual | meta
#define MAKE_CUSTOM_TLV(meta, base, actual) (TlvType)((base + actual) | meta)

typedef enum 
{
	PACKET_TLV_TYPE_REQUEST        = 0,
	PACKET_TLV_TYPE_RESPONSE       = 1,
	PACKET_TLV_TYPE_PLAIN_REQUEST  = 10,
	PACKET_TLV_TYPE_PLAIN_RESPONSE = 11,
} PacketTlvType;

// Meta argument types, used for validation
#define TLV_META_TYPE_NONE          (0 << 0)
#define TLV_META_TYPE_STRING        (1 << 16)
#define TLV_META_TYPE_UINT          (1 << 17)
#define TLV_META_TYPE_RAW           (1 << 18)
#define TLV_META_TYPE_BOOL          (1 << 19)
#define TLV_META_TYPE_GROUP         (1 << 30)
#define TLV_META_TYPE_COMPLEX       (1 << 31)
#define TLV_META_TYPE_MASK(x)       ((x) & 0xffff0000)

#define TLV_RESERVED                0
#define TLV_EXTENSIONS              20000
#define TLV_USER                    40000
#define TLV_TEMP                    60000

#define LOAD_LIBRARY_FLAG_ON_DISK   (1 << 0)
#define LOAD_LIBRARY_FLAG_EXTENSION (1 << 1)
#define LOAD_LIBRARY_FLAG_LOCAL     (1 << 2)

#define CHANNEL_FLAG_SYNCHRONOUS    (1 << 0)

typedef DWORD TlvMetaType;

typedef enum
{
	MAKE_TLV(ANY,                 TLV_META_TYPE_NONE,        0),
	MAKE_TLV(METHOD,              TLV_META_TYPE_STRING,      1),
	MAKE_TLV(REQUEST_ID,          TLV_META_TYPE_STRING,      2),
	MAKE_TLV(EXCEPTION,           TLV_META_TYPE_GROUP,       3),
	MAKE_TLV(RESULT,              TLV_META_TYPE_UINT,        4),

	// Argument basic types
	MAKE_TLV(STRING,              TLV_META_TYPE_STRING,     10),
	MAKE_TLV(UINT,                TLV_META_TYPE_UINT,       11),
	MAKE_TLV(BOOL,                TLV_META_TYPE_BOOL,       12),

	// Extended types
	MAKE_TLV(LENGTH,              TLV_META_TYPE_UINT,       25),
	MAKE_TLV(DATA,                TLV_META_TYPE_RAW,        26),
	MAKE_TLV(FLAGS,               TLV_META_TYPE_UINT,       27),

	// Channel types
	MAKE_TLV(CHANNEL_ID,          TLV_META_TYPE_UINT,       50),
	MAKE_TLV(CHANNEL_TYPE,        TLV_META_TYPE_STRING,     51),
	MAKE_TLV(CHANNEL_DATA,        TLV_META_TYPE_RAW,        52),
	MAKE_TLV(CHANNEL_DATA_GROUP,  TLV_META_TYPE_GROUP,      53),
	MAKE_TLV(CHANNEL_CLASS,       TLV_META_TYPE_UINT,       54),

	// Channel extended types
	MAKE_TLV(SEEK_WHENCE,         TLV_META_TYPE_UINT,       70),
	MAKE_TLV(SEEK_OFFSET,         TLV_META_TYPE_UINT,       71),
	MAKE_TLV(SEEK_POS,            TLV_META_TYPE_UINT,       72),

	// Grouped identifiers
	MAKE_TLV(EXCEPTION_CODE,      TLV_META_TYPE_UINT,      300),
	MAKE_TLV(EXCEPTION_STRING,    TLV_META_TYPE_STRING,    301),

	// Library loading
	MAKE_TLV(LIBRARY_PATH,        TLV_META_TYPE_STRING,    400),
	MAKE_TLV(TARGET_PATH,         TLV_META_TYPE_STRING,    401),
	MAKE_TLV(MIGRATE_PID,         TLV_META_TYPE_UINT,      402),

	// Cryptography
	MAKE_TLV(CIPHER_NAME,         TLV_META_TYPE_STRING,    500),
	MAKE_TLV(CIPHER_PARAMETERS,   TLV_META_TYPE_GROUP,     501),

	MAKE_TLV(EXTENSIONS,          TLV_META_TYPE_COMPLEX, 20000),
	MAKE_TLV(USER,                TLV_META_TYPE_COMPLEX, 40000),
	MAKE_TLV(TEMP,                TLV_META_TYPE_COMPLEX, 60000),
} TlvType;

typedef struct
{
	DWORD length;
	DWORD type;
} TlvHeader;

typedef struct
{
	TlvHeader header;
	PUCHAR    buffer;
} Tlv;

typedef struct _Packet
{
	TlvHeader header;

	PUCHAR    payload;
	ULONG     payloadLength;
} Packet;

/*
 * Packet request completion notification handler
 */
typedef DWORD (*PacketRequestCompletionRoutine)(Remote *remote, 
		Packet *response, LPVOID context, LPCSTR method, DWORD result);

typedef struct
{
	LPVOID                         context;
	PacketRequestCompletionRoutine routine;
	DWORD                          timeout;
} PacketRequestCompletion;

/*
 * Packet manipulation
 */
LINKAGE Packet *packet_create(PacketTlvType type, LPCSTR method);
LINKAGE Packet *packet_create_response(Packet *packet);
LINKAGE Packet *packet_duplicate(Packet *packet);
LINKAGE VOID packet_destroy(Packet *packet);

LINKAGE DWORD packet_add_tlv_string(Packet *packet, TlvType type, LPCSTR str);
LINKAGE DWORD packet_add_tlv_uint(Packet *packet, TlvType type, UINT val);
LINKAGE DWORD packet_add_tlv_bool(Packet *packet, TlvType type, BOOL val);
LINKAGE DWORD packet_add_tlv_group(Packet *packet, TlvType type, Tlv *entries, 
		DWORD numEntries);
LINKAGE DWORD packet_add_tlvs(Packet *packet, Tlv *entries, 
		DWORD numEntries);
LINKAGE DWORD packet_add_tlv_raw(Packet *packet, TlvType type, LPVOID buf, 
		DWORD length);
LINKAGE DWORD packet_is_tlv_null_terminated(Packet *packet, Tlv *tlv);
LINKAGE PacketTlvType packet_get_type(Packet *packet);
LINKAGE TlvMetaType packet_get_tlv_meta(Packet *packet, Tlv *tlv);
LINKAGE DWORD packet_get_tlv(Packet *packet, TlvType type, Tlv *tlv);
LINKAGE DWORD packet_get_tlv_string(Packet *packet, TlvType type, Tlv *tlv);
LINKAGE DWORD packet_get_tlv_group_entry(Packet *packet, Tlv *group, TlvType type,
		Tlv *entry);
LINKAGE DWORD packet_enum_tlv(Packet *packet, DWORD index, TlvType type, 
		Tlv *tlv);

LINKAGE PCHAR packet_get_tlv_value_string(Packet *packet, TlvType type); 
LINKAGE UINT packet_get_tlv_value_uint(Packet *packet, TlvType type); 
LINKAGE BOOL packet_get_tlv_value_bool(Packet *packet, TlvType type); 

LINKAGE DWORD packet_add_exception(Packet *packet, DWORD code,
		PCHAR string, ...);

LINKAGE DWORD packet_get_result(Packet *packet);

/*
 * Packet transmission
 */
LINKAGE DWORD packet_transmit(Remote *remote, Packet *packet,
		PacketRequestCompletion *completion);
LINKAGE DWORD packet_transmit_empty_response(Remote *remote, Packet *packet, 
		DWORD res);
LINKAGE DWORD packet_receive(Remote *remote, Packet **packet);

#define packet_transmit_response(result, remote, response)    \
	if (response) {                                            \
		packet_add_tlv_uint(response, TLV_TYPE_RESULT, result); \
		packet_transmit(remote, response, NULL);                \
	}

/*
 * Packet completion notification
 */
LINKAGE DWORD packet_add_completion_handler(LPCSTR requestId, 
		PacketRequestCompletion *completion);
LINKAGE DWORD packet_call_completion_handlers(Remote *remote, Packet *response,
		LPCSTR requestId);
LINKAGE DWORD packet_remove_completion_handler(LPCSTR requestId);

/*
 * Core API
 */
LINKAGE DWORD send_core_console_write(Remote *remote, LPCSTR fmt, ...);

#endif
