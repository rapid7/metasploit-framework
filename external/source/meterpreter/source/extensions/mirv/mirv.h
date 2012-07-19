#ifndef _METERPRETER_SOURCE_EXTENSION_MIRV_MIRV_H
#define _METERPRETER_SOURCE_EXTENSION_MIRV_MIRV_H
#include "../../common/common.h"

#define TLV_TYPE_EXTENSION_MIRV	0


#define TLV_TYPE_MIRV_LUA_CODE	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_STRING,				\
				TLV_TYPE_EXTENSION_MIRV,		\
				TLV_EXTENSIONS + 681)

#define TLV_TYPE_MIRV_LUA_RETMSG	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_STRING,				\
				TLV_TYPE_EXTENSION_MIRV,		\
				TLV_EXTENSIONS + 682)

#define TLV_TYPE_MIRV_NEWTHREAD	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_BOOL,				\
				TLV_TYPE_EXTENSION_MIRV,		\
				TLV_EXTENSIONS + 683)

#define TLV_TYPE_MIRV_RET_THREADID	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_UINT,				\
				TLV_TYPE_EXTENSION_MIRV,		\
				TLV_EXTENSIONS + 684)

#define TLV_TYPE_MIRV_THREADERR	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_STRING,				\
				TLV_TYPE_EXTENSION_MIRV,		\
				TLV_EXTENSIONS + 685)

#define TLV_TYPE_MIRV_THREADLIST	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_GROUP,				\
				TLV_TYPE_EXTENSION_MIRV,		\
				TLV_EXTENSIONS + 686)

#define TLV_TYPE_MIRV_THREADRECORD	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_STRING,				\
				TLV_TYPE_EXTENSION_MIRV,		\
				TLV_EXTENSIONS + 687)

#define MAX_MIRV_THREADS 256

enum thread_signal {
		run,
		stop,
		report
};

 struct mirv_thread_t {
	DWORD thread_id;
	char *description;
	enum thread_signal signal; 
};
typedef  struct mirv_thread_t mirv_thread;

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383
#define MAX_VALUE_DATA 65535
#define MAX_RESOURCES 1024
#define MAX_WAIT_HANDLES 256
#define MAX_WAIT_TIME 1000 // 1 sec
typedef struct messageProviders_struct {
	char* providerNameBestGuess;
	char* CategoryMessageFile;
	char* EventMessageFile;
	char* ParameterMessageFile;
} messageProvider;

int getProviders(messageProvider **mpArray);
unsigned int getEventLogProviders(char **providers);


typedef struct event_reader_struct {
	HANDLE resources[1024];
	DWORD resourceHandleCount;
	HANDLE aWaitHandles[MAX_WAIT_HANDLES];
	HANDLE eventLoghandles[MAX_WAIT_HANDLES];
} event_reader;

int open_log(char *provider, event_reader *er_out);
int get_event(event_reader *er, char **message);
int close_log(event_reader *er);
#endif