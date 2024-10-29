#include <windows.h>
#include <stdlib.h>

#include "byakugan.h"
#include "tenketsu.h"
#include "heapStructs.h"

#define BUFSIZE		4096

// UNDOCUMENTED FUNCTIONS TO ADD
//
//		RtlAllocateMemoryBlockLookaside
//		RtlFreeMemoryBlockLookaside
//		
//		RtlCreateMemoryBlockLookaside
//		RtlDestroyMemoryBlockLookaside
//		
//		RtlExtendMemoryBlockLookaside
//		RtlResetMemoryBlockLookaside

PCSTR	undocdFunc[] = { "ntdll!RtlpCoalesceFreeBlocks", NULL };
ULONG	undocdAddr[sizeof (undocdFunc)+1];

struct HeapState		heapModel;
BOOLEAN					running = FALSE;

// Two things that fucking rock? Bunnies and Jaguars. Werd.


int hookRtlHeap(BYTE type, char *fileName) {
    HRESULT     Status;
    HANDLE      process;
    DWORD       pid;
    HANDLE processHandle = 0;
    HANDLE threadHandle = 0;
    LPVOID stringAddress = NULL;
    LPCSTR dllName = "C:\\windbg\\injectsu.dll";
    ULONG64     funcAddr64;
    ULONG       *funcAddr, i;

	heapModel.state = heapModel.state ^ type;

	if (running) {
		dprintf("[Byakugan] Hooks are already injected.\n");
		return (0);
	}

	running = TRUE;

	dprintf("[Byakugan] Beginning data gathering thread... ");
	if(tenkListener()) {
		dprintf("\n[Byakugan] Failed to create heap info back channel :(\n");
		VirtualFreeEx(processHandle, stringAddress, strlen(dllName), MEM_DECOMMIT);
        CloseHandle(processHandle); 
        return (-1);	
	}
   	dprintf("Success!\n[Byakugan] Injecting Tenketsu Heap Monitoring DLL... ");
    
	Status = g_ExtSystem->GetCurrentProcessSystemId(&pid);
    if (Status != S_OK)
        return (-1);

    if(!(processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid))){
        dprintf("\n[Byakugan] Unable to OpenProcess().\n");
        return (-1);
    }

    if(!(stringAddress = VirtualAllocEx(processHandle, NULL, strlen(dllName), MEM_COMMIT, PAGE_EXECUTE_READWRITE))){
        printf("\n[Byakugan] VirtualAllocEx() failed.\n");
        CloseHandle(processHandle);
        return (-1);
    }

    if(!WriteProcessMemory(processHandle, (LPVOID)stringAddress, dllName, strlen(dllName), NULL)){
        dprintf("\n[Byakugan] WriteProcessMemory() failed.\n");
        VirtualFreeEx(processHandle, stringAddress, strlen(dllName), MEM_DECOMMIT);
        CloseHandle(processHandle);
        return (-1);
    }

    dprintf("Success!\n");

	// Resolve undocumented functions!	
    i = 0;
	g_ExtSymbols->Reload("/f ntdll.dll");
	dprintf("[Byakugan] Resolving undocumented Heap functions...\n");
    while (undocdFunc[i] != NULL) {
		if (g_ExtSymbols->GetOffsetByName(undocdFunc[i], &funcAddr64) == E_FAIL)
			funcAddr64 = NULL;
		funcAddr = (ULONG *) &funcAddr64;
        if (*funcAddr != NULL)
            dprintf("[T] Resolved undocumented function '%s' @ 0x%08x.\n", undocdFunc[i], *funcAddr);
        else
            dprintf("[T] Unable to resolve undocumented function '%s' :(\n", undocdFunc[i]);
        undocdAddr[i] = *funcAddr;
        i++;
    }
    undocdAddr[i] = NULL;


    if(!(threadHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibrary("kernel32.dll"), "LoadLibraryA"), \
                (LPVOID)stringAddress, 0, NULL))){
        dprintf("\n[Byakugan] CreateRemoteThread() failed.\n");
        VirtualFreeEx(processHandle, stringAddress, strlen(dllName), MEM_DECOMMIT);
        CloseHandle(processHandle);
        return (-1);
    }

	CloseHandle(threadHandle);
    CloseHandle(processHandle);

	// Set up the log file
	if (type == 2) {
		heapModel.hLogFile = CreateFileA(fileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!heapModel.hLogFile) {
			dprintf("[T] Unable to open file \"%s\" for writing. :(\n");
		}
	}

    return (0);
}

int tenkListener(void) {
   	BOOL fConnected; 
   	DWORD dwThreadId; 
   	HANDLE hPipe, hThread; 
   	LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\tenketsu"); 

	
	hPipe = CreateNamedPipe(	lpszPipename,
								PIPE_ACCESS_DUPLEX,
								PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
								PIPE_UNLIMITED_INSTANCES,
								BUFSIZE,
								BUFSIZE,
								NMPWAIT_USE_DEFAULT_WAIT,
								NULL);
	
	if (hPipe == INVALID_HANDLE_VALUE) {
		dprintf("[Byakugan] CreateNamedPipe() failed.\n");
		return (-1);
	}
    

	hThread = CreateThread(		NULL,
								0,
								tenkBackChannel,
								(LPVOID) hPipe,
								0,
								&dwThreadId);

    if (hThread == NULL) {
        dprintf("[Byakugan] CreateThread() failed.\n");
        return (-1);
    } 


	CloseHandle(hThread);



	return (0);
}

DWORD WINAPI tenkBackChannel(LPVOID lpvParam) {
	HANDLE		hPipe;
	TCHAR		buf[BUFSIZE+1];
	ULONG		bytesRead, bytesWritten;
	BOOL		fSuccess;
	ULONG64		funcAddr64;
	ULONG		*funcAddr, i;
	

	struct AllocateStruct	*aStruct = (struct AllocateStruct *)buf;
	struct ReallocateStruct	*rStruct = (struct ReallocateStruct *)buf;
	struct FreeStruct		*fStruct = (struct FreeStruct *)buf;
	struct CreateStruct		*cStruct = (struct CreateStruct *)buf;
	struct DestroyStruct	*dStruct = (struct DestroyStruct *)buf;
	struct CoalesceStruct	*cfbStruct = (struct CoalesceStruct *)buf;

	
	hPipe = (HANDLE) lpvParam;
	
	dprintf("[Byakugan] Waiting for named pipe connection...\n");

	for(;!ConnectNamedPipe(hPipe, NULL) == TRUE;) { dprintf("[B] waiting for connection...\n"); }

	dprintf("[Byakugan] Connected to back channel. :)\n");

	// Load addresses from symbols if possible for undoumented interfaces
	i = 0;
	while (undocdFunc[i] != NULL) {
		dprintf("[T] Sending address of %s\n", undocdFunc[i]);
		fSuccess = WriteFile(hPipe, &(undocdAddr[i]), sizeof(ULONG), &bytesWritten, NULL);
		if (!fSuccess || bytesWritten != sizeof(ULONG))
			dprintf("[T] Failed to send address of %s\n", undocdFunc[i]);
		i++;
	}
	//FlushFileBuffers(hPipe);
	dprintf("[T] Sent addresses of %d undocumented functions.\n", i);

	initializeHeapModel(&heapModel);

#undef THREEDHEAPFU_ENABLED //Place this in setup.bat

#if 0 //#ifdef THREEDHEAPFU_ENABLED
//Create a heap event proxy, play these back out to 3dheapfu
LPTSTR	lpszProxyPipename = TEXT("\\\\.\\pipe\\tenketsuProxy");
BOOL	fProxySuccess;
DWORD	dwProxyMode	= PIPE_READMODE_MESSAGE;
ULONG   bytesProxyWritten;
static BOOL	fDontAttemptProxyWrite = false;

HANDLE hProxyPipe = CreateFile(lpszProxyPipename,
								GENERIC_READ | GENERIC_WRITE,
								0,
								NULL,
								OPEN_EXISTING,
								0,
								NULL);

			if (hProxyPipe == INVALID_HANDLE_VALUE)
					dprintf("hProxyPipe == invalid handle\n");
			else
					dprintf("hProxyPipe == good\n");
			SetNamedPipeHandleState(hProxyPipe, &dwProxyMode, NULL, NULL); //?

#endif

	while (1) {
		fSuccess = ReadFile(	hPipe,
								buf,
								BUFSIZE*sizeof(TCHAR),
								&bytesRead,
								NULL);
		if (!fSuccess || bytesRead == 0) {
			dprintf("[Byakugan] ReadFile failed, or read 0 bytes.\n");
			continue;
		}
#if 0 //#ifdef THREEDHEAPFU_ENABLED
		//dprintf("jc: receieved an event of size %d. Forwarding on to ProxyPipe\n", bytesRead);
		//WriteFile(hPipe, &freeinfo, sizeof(struct FreeStruct), &bytesWritten, NULL);

		if (!fDontAttemptProxyWrite)
		{
			fProxySuccess = WriteFile(hProxyPipe, buf, bytesRead, &bytesProxyWritten, NULL); 
			if (bytesRead != bytesProxyWritten)
			{
				dprintf("Partial write to proxy on last event! ;(\n");
				dprintf("event size was %d. wrote %d\n", bytesRead, bytesProxyWritten);
				dprintf("Disabling message proxying until explicitly enabled.\n");
				fDontAttemptProxyWrite = true;
			}
		}

#endif
		switch ( *((BYTE *) buf) ) {
			case ALLOCATESTRUCT:
				//dprintf("[T] New Chunk @ 0x%08x\n", aStruct->ret);
				//dprintf("Heap: 0x%08x\tFlags: 0x%08x\tSize: 0x%08x\n\n", 
				//		aStruct->heapHandle, aStruct->flags, aStruct->size);
				if (heapModel.state & MODEL) heapAllocate(&heapModel, aStruct);
				if (heapModel.state & LOG) logAllocate(&heapModel, aStruct);
				break;

			case REALLOCATESTRUCT:
				//dprintf("[T] Realloc'd Chunk @ 0x%08x\n", rStruct->ret);
				//dprintf("Heap: 0x%08x\tFlags: 0x%08x\tSize: 0x%08x\n", 
				//		rStruct->heapHandle, rStruct->flags, rStruct->size);
				//if (rStruct->ret !=  (PVOID) rStruct->memoryPointer)
				//	dprintf("Replaces chunk @ 0x%08x\n", rStruct->memoryPointer);
				//dprintf("\n");
				if (heapModel.state & MODEL) heapReallocate(&heapModel, rStruct);
				if (heapModel.state & LOG) logReallocate(&heapModel, rStruct);
				break;

			case FREESTRUCT:
				//dprintf("[T] Free'd Chunk @ 0x%08x\n", fStruct->memoryPointer);
				//dprintf("Heap: 0x%08x\tFlags: 0x%08x\n\n", fStruct->heapHandle, fStruct->flags);
				if (heapModel.state & MODEL) heapFree(&heapModel, fStruct);
				if (heapModel.state & LOG) logFree(&heapModel, fStruct);
				break;

			case CREATESTRUCT:
				dprintf("[T] New Heap: 0x%08x\n", cStruct->ret);
				dprintf("Base: 0x%08x\tReserve: 0x%08x\tFlags: 0x%08x\n",
						cStruct->base, cStruct->reserve, cStruct->flags);
				//dprintf("Commit: 0x%08x\tLock: 0x%08x\n\n", cStruct->commit, cStruct->lock);
				if (heapModel.state & MODEL) heapCreate(&heapModel, cStruct);
				break;

			case DESTROYSTRUCT:
				dprintf("[T] Heap Destroyed: 0x%08x\n\n", dStruct->heapHandle);
				if (heapModel.state & MODEL) heapDestroy(&heapModel, dStruct);
				break;
			
			case COALESCESTRUCT:
				//dprintf("[T] Free Block Consolidation (returned 0x%08x)\n", cfbStruct->ret);
				//dprintf("Heap: 0x%08x\tArg2: 0x%08x\tArg3: 0x%08x\tArg4: 0x%08x\n\n",
				//		cfbStruct->heapHandle, cfbStruct->arg2, cfbStruct->arg3, cfbStruct->arg4);
				if (heapModel.state & MODEL) heapCoalesce(&heapModel, cfbStruct);
				break;

			default:
				dprintf("[Byakugan] Tenketsu: Unrecognized data was returned.\n");
		}

	}


	return (0);
}

void tenkHelp() {
	dprintf(HELPSTRING);
	dprintf("Tenketsu Commands:\n");
	dprintf("\tmodel\t- Load tenketsu heap visualization libraries and begin modeling\n");
	dprintf("\tlog\t- Load tenketsu heap visualization libraries and begin logging\n");
	dprintf("\tlistHeaps\t- List all currently tracked heaps and their information\n");
	dprintf("\tlistChunks <heap base>\t- List all chunks associated with a givend heap\n");
	dprintf("\tvalidate <heap base> - check the chunk chain and find corrupted chunk headers\n");
}

void tenkListHeaps() {
	struct HPool	*curHeap;
	ULONG			i;

	dprintf("[T] Currently tracking %d heaps:\n", heapModel.numHeaps);
	for (i = 0; i < heapModel.numHeaps; i++) {
		curHeap = &(heapModel.heaps[i]);
		if (curHeap->inUse == FALSE)
			continue;
		dprintf("\tBase: 0x%08x\tNumber of Chunks: %d\n", curHeap->base, curHeap->numChunks);
		dprintf("\tFlags: 0x%08x\tReserve: 0x%08x\n", 
				curHeap->flags, curHeap->reserve, curHeap->commit);
		dprintf("\tLock: 0x%08x\n\n", curHeap->lock);
	}
}

void tenkValidate(PVOID heapHandle) {
	struct HPool            *heap;
    struct DestroyStruct    dStruct;
    struct HeapChunk        *curChunk;
	ULONG					chunkPtr;
    ULONG                   i, nextIndex;
	BOOL					screwed = FALSE;

	heap = getHeap(&heapModel, heapHandle);

	i = heap->inUseHead;
	while (i != NULLNODE) {
		if (CHUNK(i).free) {
			// CHUNK(i).nextInUse must be equal to the next ptr
			if(!ReadMemory((ULONG64)(CHUNK(i).addr)+4, (PVOID) &chunkPtr, 4, NULL)) {
				dprintf("[T] Unable to read memory at address 0x%08x\n!");
				return;
			}

			// Find next free chunk - continue if there are no more
			nextIndex = CHUNK(i).nextInUse;
			while (nextIndex != NULLNODE && !(CHUNK(nextIndex).free))
				nextIndex = CHUNK(nextIndex).nextInUse;
			if (nextIndex == NULLNODE) {
				i = CHUNK(i).nextInUse;
				continue;
			}

			// Validate next free chunk
			if (CHUNK(nextIndex).addr != (PVOID) chunkPtr) {
				dprintf("[T] Corruped next pointer for chunk at 0x%08x\n", CHUNK(i).addr);
				dprintf(">\tGot: 0x%08x\tExpected: 0x%08x\n", chunkPtr, CHUNK(nextIndex).addr);
				screwed = TRUE;
			}
			
			// next free chunk prev, must equal CHUNK(i).addr
			if(!ReadMemory((ULONG64)CHUNK(nextIndex).addr, (PVOID) &chunkPtr, 4, NULL)) {
                dprintf("[T] Unable to read memory at address 0x%08x\n!");
                return; 
            }
			if ((PVOID) chunkPtr != CHUNK(i).addr) {
                dprintf("[T] Corruped prev pointer for chunk at 0x%08x\n", CHUNK(nextIndex).addr);
                dprintf(">\tGot: 0x%08x\tExpected: 0x%08x\n", chunkPtr, CHUNK(i).addr);
				screwed = TRUE;
			}
		
		
		} else {
		}
		i = CHUNK(i).nextInUse;
	}
	
	dprintf("[T] Validation complete: ");
	if (!screwed)
		dprintf("all known free chunks are correct\n");
	else
		dprintf("errors found\n");
}

void tenkListChunks(PVOID heapHandle) {
	struct HPool			*heap;
	struct DestroyStruct	dStruct;
	struct HeapChunk		*curChunk;
	ULONG					i;

	heap = getHeap(&heapModel, heapHandle);
	dprintf("[T] Currently tracking %d chunks for heap 0x%08x\n", 
			heap->numChunks, heap->base);
	
	i = heap->inUseHead;
	while (i != NULLNODE) {
		if (CHUNK(i).inUse) {
			dprintf("\tAddress: 0x%08x\tSize: 0x%08x", CHUNK(i).addr, CHUNK(i).size);
			dprintf("\tFlags: 0x%08x\t%s\n\n", CHUNK(i).flags, 
					(CHUNK(i).free)?"FREE'D":"IN USE");
		}
		i = CHUNK(i).nextInUse;
	}

	if (heap->numChunks == 0) {
		dStruct.heapHandle	= heap->base;
		heapDestroy(&heapModel, &dStruct);
	}
}
