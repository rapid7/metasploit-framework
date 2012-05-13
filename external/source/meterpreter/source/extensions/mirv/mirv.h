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
		stop,
		report
};

 struct mirv_thread_t {
	DWORD thread_id;
	char *description;
	enum thread_signal signal; 
};
typedef  struct mirv_thread_t mirv_thread;

#endif