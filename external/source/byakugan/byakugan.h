#include <windows.h>
#include <winerror.h>

#include <string.h>
#include <strsafe.h>

#include <stdio.h>
#include <stdlib.h>

//
// Define KDEXT_64BIT to make all wdbgexts APIs recognize 64 bit addresses
// It is recommended for extensions to use 64 bit headers from wdbgexts so
// the extensions could support 64 bit targets.
//
// So says MS.... Hopefully the new extension API will do a better job
// than the legacy API at this....
//
#define KDEXT_64BIT
#include <wdbgexts.h>
#include <dbgeng.h>

#pragma warning(disable:4201) // nonstandard extension used : nameless struct
#include <extsfns.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HELPSTRING "Byakugan - Increase your Sight\nPusscat / Lin0xx\n\n"


#define INIT_API()                             \
    HRESULT Status;                            \
    if ((Status = ExtQuery(Client)) != S_OK) return Status;

#define EXT_RELEASE(Unk) \
    ((Unk) != NULL ? ((Unk)->Release(), (Unk) = NULL) : NULL)

#define EXIT_API     ExtRelease

#define NTSTATUS ULONG
#define STATUS_NO_MORE_ENTRIES	((NTSTATUS)0x8000001AL)

// Global variables initialized by query.
extern PDEBUG_CLIENT4   g_ExtClient;
extern PDEBUG_CONTROL	g_ExtControl;
extern PDEBUG_SYMBOLS3	g_ExtSymbols;
extern PDEBUG_SYSTEM_OBJECTS2  g_ExtSystem;
extern PDEBUG_DATA_SPACES g_ExtData;

extern BOOL  Connected;
extern ULONG TargetMachine;
extern ULONG64 disassemblyBuffer;

HRESULT
ExtQuery(PDEBUG_CLIENT4 Client);

void
ExtRelease(void);

HRESULT
NotifyOnTargetAccessible(PDEBUG_CONTROL Control);

#ifdef __cplusplus
}
#endif
