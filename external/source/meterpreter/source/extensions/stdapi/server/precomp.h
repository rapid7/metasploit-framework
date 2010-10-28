#ifndef METERPRETER_SOURCE_EXTENSION_STDAPI_SERVER_PRECOMP_H
#define METERPRETER_SOURCE_EXTENSION_STDAPI_SERVER_PRECOMP_H

#ifdef _WIN32
// sf: Compatability fix for a broken sdk? We get errors in Iphlpapi.h using the latest Windows SDK if we dont do this.
 #define  _WIN32_WINNT _WIN32_WINNT_WIN2K
 #include "../stdapi.h"
 #include <tlhelp32.h>
 #include <iphlpapi.h>
 #include "resource/resource.h"
#else
 #include <sys/mman.h>
 #include "../stdapi.h"
 #include <unistd.h>
 #include <stdlib.h>
 #include <sys/socket.h>
 #include <sys/stat.h>
 #include <netdb.h>
 #include <netinet/in.h>
 #include <stdarg.h>
 #include <fcntl.h>
 #include <sys/wait.h>
 #include <termios.h>

 #include <pcap/pcap.h>

 #include <linux/if.h>
 #include <linux/netlink.h>
 #include <linux/elf.h>


#define IN_ADDR struct in_addr
#define SOCKADDR_IN struct sockaddr_in
#define SOCKADDR struct sockaddr
#define WSAEventSelect(a,b,c) (0xcafebabe)

#define SOCKET_ERROR (-1)

#define WSAECONNRESET ECONNRESET
#define WSAECONNABORTED ECONNABORTED

#define BREAK_WITH_ERROR(format, args...) \
	do { \
		dprintf(format, ## args); \
		exit(0); \
	} while(0) \

#define BREAK_ON_WSAERROR(format, args...) \
	do { \
		dprintf(format, ## args); \
		abort(); \
	} while(0) \

#define Sleep(x) usleep(x * 1000)
#define WSASocket(a,b,c,d,e,f) socket(a,b,c)
#define WSACreateEvent()  (0x5a5a5a5a)
#define WSA_INVALID_EVENT (0xa5a5a5a5)
#define WSAResetEvent(x)
#define ResetEvent(x)
#endif


#include "fs/fs.h"
#include "sys/sys.h"
#include "net/net.h"
#include "ui/ui.h"

#ifdef _WIN32
 #include "railgun/railgun.h"	// PKS, win32 specific at the moment.

 #include "../../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
 #include "../../../ReflectiveDLLInjection/GetProcAddressR.h"
 #include "../../../ReflectiveDLLInjection/ReflectiveLoader.h"
 // declared in ReflectiveLoader.c and set by DllMain also in ReflectiveLoader.c
 extern HINSTANCE hAppInstance;
#endif

#define strcasecmp _stricmp


#endif
