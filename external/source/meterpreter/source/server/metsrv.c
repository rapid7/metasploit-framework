#include "metsrv.h"

#ifdef _WIN32

#include <windows.h> // for EXCEPTION_ACCESS_VIOLATION 
#include <excpt.h> 

// include the OpenSSL library
#pragma comment(lib,"libeay32.lib")
#pragma comment(lib,"ssleay32.lib")
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
DWORD __declspec(dllexport) Init(SOCKET fd, void *base)
{

	metsrv_rtld(fd, base);
}

#endif
