#ifndef _METERPRETER_CLIENT_METCLI_H
#define _METERPRETER_CLIENT_METCLI_H

#include "../common/common.h"

#include "console.h"
#include "module.h"

VOID client_init_lock();
VOID client_acquire_lock();
VOID client_release_lock();

#endif
