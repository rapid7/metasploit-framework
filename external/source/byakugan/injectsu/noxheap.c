#include <windows.h>
#include <detours.h>
#define NTSTATUS ULONG

#include "../heapStructs.h"

/* NoxHeapINT(ELLiGENCE) - because heap stupidity means no 0day
 * (or Tenketsu)
 * ------------------------------------------------------------
 * By Lin0xx / Pusscat
 * ------------------------------------------------------------
 * This dll is intended to be injected into a target
 * application whose heap allocations, reallocations, and frees
 * need to be tracked.  The end goal for this program is to be
 * able to communicate to a visualization server that will draw
 * the heap as it is in real time.  This view of the heap can
 * then be diff'd via walking the heap by finding the heap base
 * in the process environment block.  By doing this, one will
 * be able to understand how an application is molding the heap
 * along with the nature of the overflow in question.  
 */

/* Build instructions:
 * C:\share\noxHeap>cl noxheap.c /LD /link "C:\Program Files\Microsoft Research\Detours Express 2.1\lib\detours.lib" "C:\Program Files\Microsoft Research\Detours Express 2.1\lib\detoured.lib"
 * -------------------------
 * This assumes all of the libraries for detours have been built correctly
 * Please copy detours.dll into C:\WINDOWS\System32
 */

#define NTSTATUS	ULONG
#define BUFSIZE		4096
/* UNDOCUMENTED HEAP STRUCTURES */

typedef struct _RTL_HEAP_DEFINITION {
  ULONG                   Length;
  ULONG                   Unknown1;
  ULONG                   Unknown2;
  ULONG                   Unknown3;
  ULONG                   Unknown4;
  ULONG                   Unknown5;
  ULONG                   Unknown6;
  ULONG                   Unknown7;
  ULONG                   Unknown8;
  ULONG                   Unknown9;
  ULONG                   Unknown10;
  ULONG                   Unknown11;
  ULONG                   Unknown12;
} RTL_HEAP_DEFINITION, *PRTL_HEAP_DEFINITION;


LPTSTR	lpszPipename	= TEXT("\\\\.\\pipe\\tenketsu"); 
HANDLE	hPipe;			
DWORD	dwMode			= PIPE_READMODE_MESSAGE;
DWORD	bytesWritten;

/* Functions to be hooked */
PVOID (WINAPI *realRtlAllocateHeap)(PVOID heapHandle, ULONG flags, ULONG size);
PVOID (WINAPI *realRtlReallocateHeap)(PVOID heapHandle, ULONG flags, PVOID memoryPointer, ULONG size);
PVOID (WINAPI *realRtlFreeHeap)(PVOID heapHandle, ULONG flags, PVOID memoryPointer);

PVOID (WINAPI *realRtlCreateHeap)(ULONG flags, PVOID base, ULONG reserve, ULONG commit, BOOLEAN lock, PRTL_HEAP_DEFINITION RtlHeapParams);

NTSTATUS (WINAPI *realRtlDestroyHeap)(PVOID heapHandle);
PVOID (WINAPI *realRtlpCoalesceFreeBlocks)(PVOID, ULONG, ULONG, ULONG);

/* TO ADD:
 * RtlAllocateMemoryBlockLookaside
 * RtlpCoalesceFreeBlocks
 */

/* End hooking section */

PVOID WINAPI noxRtlFreeHeap(PVOID heapHandle, ULONG flags, PVOID memoryPointer){
	PVOID	ret;
	struct FreeStruct	freeinfo;

	ret = (*realRtlFreeHeap)(heapHandle, flags, memoryPointer);

	freeinfo.type			= FREESTRUCT;
	freeinfo.heapHandle		= heapHandle;
	freeinfo.flags			= flags;
	freeinfo.memoryPointer	= memoryPointer;
	freeinfo.ret			= ret;

	WriteFile(hPipe, &freeinfo, sizeof(struct FreeStruct), &bytesWritten, NULL);
	
	return (ret);

}

PVOID WINAPI noxRtlReallocateHeap(PVOID heapHandle, ULONG flags, PVOID memoryPointer, ULONG size){
	PVOID	ret;
	struct	ReallocateStruct	reallocinfo;
	
	ret = (*realRtlReallocateHeap)(heapHandle, flags, memoryPointer, size);
    reallocinfo.type          = REALLOCATESTRUCT;
    reallocinfo.heapHandle    = heapHandle;
    reallocinfo.flags         = flags;
    reallocinfo.memoryPointer = memoryPointer;
    reallocinfo.size          = size;
    reallocinfo.ret           = ret;

    WriteFile(hPipe, &reallocinfo, sizeof(struct ReallocateStruct), &bytesWritten, NULL);

	return (ret);
}

PVOID WINAPI noxRtlAllocateHeap(PVOID heapHandle, ULONG flags, ULONG size){
	PVOID	ret;
	struct	AllocateStruct allocinfo;

	ret = (*realRtlAllocateHeap)(heapHandle, flags, size);

	allocinfo.type			= ALLOCATESTRUCT;
	allocinfo.heapHandle	= heapHandle;
	allocinfo.flags			= flags;
	allocinfo.size			= size;
	allocinfo.ret			= ret;

	WriteFile(hPipe, &allocinfo, sizeof(struct AllocateStruct), &bytesWritten, NULL);

	return (ret);
}

PVOID WINAPI noxRtlCreateHeap(	ULONG flags, 
								PVOID base, 
								ULONG reserve, 
								ULONG commit, 
								BOOLEAN lock, 
								PRTL_HEAP_DEFINITION RtlHeapParams) {
	PVOID	ret;
	struct	CreateStruct	createinfo;

	ret = (*realRtlCreateHeap)(flags, base, reserve, commit, lock, RtlHeapParams);

	createinfo.type				= CREATESTRUCT;
	createinfo.flags			= flags;
	createinfo.base				= base;
	createinfo.reserve			= reserve;
	createinfo.commit			= commit;
	createinfo.lock				= lock;
	createinfo.RtlHeapParams	= RtlHeapParams;
	createinfo.ret				= ret;

	WriteFile(hPipe, &createinfo, sizeof(struct CreateStruct), &bytesWritten, NULL);

	return (ret);
}

NTSTATUS WINAPI noxRtlDestroyHeap(PVOID heapHandle) {
	NTSTATUS	ret;
	struct 	DestroyStruct	destroyinfo;

	ret = (*realRtlDestroyHeap)(heapHandle);

	destroyinfo.type		= DESTROYSTRUCT;
	destroyinfo.heapHandle	= heapHandle;
	destroyinfo.ret			= ret;

	WriteFile(hPipe, &destroyinfo, sizeof(struct DestroyStruct), &bytesWritten, NULL);
	
	return (ret);
}

// PLACEHOLDER FUNCTION
PVOID WINAPI noxRtlpCoalesceFreeBlocks(PVOID heapHandle, ULONG arg2, ULONG arg3, ULONG arg4) {
	struct CoalesceStruct	coalesceinfo;
	PVOID					ret;

	coalesceinfo.type		= COALESCESTRUCT;
	coalesceinfo.heapHandle	= heapHandle;
	coalesceinfo.arg2		= arg2;
	coalesceinfo.arg3		= arg3;
	coalesceinfo.arg4		= arg4;

	WriteFile(hPipe, &coalesceinfo, sizeof(struct CoalesceStruct), &bytesWritten, NULL);

	ret = (*realRtlpCoalesceFreeBlocks)(heapHandle, arg2, arg3, arg4);

	return (ret);
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD attachReason, LPVOID reserved) {
	ULONG		bytesRead;
	TCHAR		buf[BUFSIZE];
	NTSTATUS	fSuccess;

	if(attachReason == DLL_PROCESS_ATTACH){
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		/* There's no other way to find these addresses than dynamically */
		realRtlAllocateHeap = DetourFindFunction("ntdll.dll", "RtlAllocateHeap");
		realRtlReallocateHeap = DetourFindFunction("ntdll.dll", "RtlReAllocateHeap");
		realRtlFreeHeap = DetourFindFunction("ntdll.dll", "RtlFreeHeap");
		realRtlCreateHeap = DetourFindFunction("ntdll.dll", "RtlCreateHeap");
		realRtlDestroyHeap = DetourFindFunction("ntdll.dll", "RtlDestroyHeap");
	
		

		/* Start hooking */
		DetourAttach(&(PVOID)realRtlAllocateHeap, noxRtlAllocateHeap);
		DetourAttach(&(PVOID)realRtlReallocateHeap, noxRtlReallocateHeap);
		DetourAttach(&(PVOID)realRtlFreeHeap, noxRtlFreeHeap);
		DetourAttach(&(PVOID)realRtlCreateHeap, noxRtlCreateHeap);
		DetourAttach(&(PVOID)realRtlDestroyHeap, noxRtlDestroyHeap);
		//while (1) {
			hPipe = CreateFile(	lpszPipename,
								GENERIC_READ | GENERIC_WRITE,
								0,
								NULL,
								OPEN_EXISTING,
								0,
								NULL);

			if (hPipe == INVALID_HANDLE_VALUE)	// got a handle, so we're done
				__asm {int 3}

		//	WaitNamedPipe(lpszPipename, 2000);	// Wait two seconds before retry
		//}
		SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);
		
		// Get addresses of unexposed heap functions if the debugger has symbols
		ReadFile(	hPipe,
                    &realRtlpCoalesceFreeBlocks,
                    //BUFSIZE*sizeof(TCHAR),
                    4,
					&bytesRead,
                    NULL);
		if (realRtlpCoalesceFreeBlocks != NULL)
			DetourAttach(&(PVOID)realRtlpCoalesceFreeBlocks, noxRtlpCoalesceFreeBlocks);
		
		//FlushFileBuffers(hPipe);

		DetourTransactionCommit();

	}

	if(attachReason == DLL_PROCESS_DETACH){
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		
		/* Start unhooking */
		DetourDetach(&(PVOID)realRtlAllocateHeap, noxRtlAllocateHeap);
		DetourDetach(&(PVOID)realRtlReallocateHeap, noxRtlReallocateHeap);
		DetourDetach(&(PVOID)realRtlFreeHeap, noxRtlFreeHeap);
		DetourDetach(&(PVOID)realRtlCreateHeap, noxRtlCreateHeap);
		DetourDetach(&(PVOID)realRtlDestroyHeap, noxRtlDestroyHeap);

		DetourTransactionCommit();
	}

	return TRUE;
}


