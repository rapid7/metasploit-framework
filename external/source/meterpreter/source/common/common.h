#ifndef _METERPRETER_SOURCE_COMMON_COMMON_H
#define _METERPRETER_SOURCE_COMMON_COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
	#include <winsock2.h>
	#include <windows.h>
#endif

#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/havege.h"

#include "linkage.h"

#include "args.h"
#include "buffer.h"
#include "base.h"
#include "core.h"
#include "remote.h"

#include "channel.h"
#include "scheduler.h"


static void dprintf(char *format, ...) {
  va_list args;
  char buffer[1024];
  va_start(args,format);

  vsnprintf(buffer, sizeof(buffer)-3, format,args);
  strcat(buffer, "\r\n");
  OutputDebugString(buffer);
  }

	

#endif
