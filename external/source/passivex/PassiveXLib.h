/*
 *  This file is part of the Metasploit Exploit Framework
 *  and is subject to the same licenses and copyrights as
 *  the rest of this package.
 */

#ifndef _PASSIVEXLIB_H
#define _PASSIVEXLIB_H

#define _WIN32_WINNT 0x0400
#define _ATL_APARTMENT_THREADED

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <wininet.h>
#include <time.h>

#include <atlbase.h>

extern CComModule _Module;

#include <atlcom.h>
#include <atlctl.h>

#include "resource.h"
#include "PassiveX.h"
#include "CPassiveX.h"

#endif
