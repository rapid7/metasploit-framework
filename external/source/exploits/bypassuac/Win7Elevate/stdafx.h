// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"


#if defined _M_IX86

#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")

#elif defined _M_X64

#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")

#endif



#include <windows.h>

#include <commctrl.h>
#include <shlobj.h>

#include <Tlhelp32.h>

#include <stdlib.h>
#include <tchar.h>
#include <assert.h>

#include <string>
#include <list>
#include <map>

#ifndef FOFX_REQUIREELEVATION
#define FOFX_REQUIREELEVATION (0x10000000)
#endif

#ifndef FOFX_DONTDISPLAYLOCATIONS
#define FOFX_DONTDISPLAYLOCATIONS (0x80000000)
#endif
