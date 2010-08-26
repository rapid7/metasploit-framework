#include "metsrv.h"

#ifdef _WIN32

#include <windows.h> // for EXCEPTION_ACCESS_VIOLATION 
#include <excpt.h> 

#define	UnpackAndLinkLibs(p, s)

#endif

/*
 * Entry point for the DLL (or not if compiled as an EXE)
 */
#ifdef _WIN32
DWORD __declspec(dllexport) Init(SOCKET fd)
{

	return server_setup(fd);

}
#else

// rtld dynamically links libc/libm/libcrypto/libssl/metsrv_main
// then calls server_setup for us ;D

#endif
