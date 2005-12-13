#ifndef _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_H
#define _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_H

#include "../../common/common.h"

#define TLV_TYPE_EXTENSION_PRIV 0
#define TLV_EXTENSIONS                 20000

#define TLV_TYPE_SAM_HASHES            \
		MAKE_CUSTOM_TLV(                 \
				TLV_META_TYPE_STRING,      \
				TLV_TYPE_EXTENSION_PRIV,   \
				TLV_EXTENSIONS + 1)

#endif
