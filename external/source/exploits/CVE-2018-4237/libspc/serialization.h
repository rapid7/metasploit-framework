#ifndef _SERIALIZATION_H_
#define _SERIALIZATION_H_

#include "datatypes.h"

#include <mach/mach.h>

typedef struct _spc_mach_message_t {
        mach_msg_header_t header;
        unsigned char buf[];           // variable sized body
} spc_mach_message_t;

// Serializes the given dictionary into a spc_mach_message_t.
// The returned pointer has to be free()d by the caller.
spc_mach_message_t* spc_serialize(spc_message_t* msg);

spc_message_t* spc_deserialize(spc_mach_message_t* msg);

#endif
