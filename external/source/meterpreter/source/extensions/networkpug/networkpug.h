#ifndef NETWORKPUG_H
#define NETWORKPUG_H

#define TLV_TYPE_EXTENSION_NETWORKPUG      0

#define TLV_TYPE_NETWORKPUG_INTERFACE				\
                MAKE_CUSTOM_TLV(				\
                                TLV_META_TYPE_STRING,		\
                                TLV_TYPE_EXTENSION_NETWORKPUG,	\
                                TLV_EXTENSIONS + 1)

#define TLV_TYPE_NETWORKPUG_FILTER				\
                MAKE_CUSTOM_TLV(				\
                                TLV_META_TYPE_STRING,		\
                                TLV_TYPE_EXTENSION_NETWORKPUG,	\
                                TLV_EXTENSIONS + 2)

#endif
