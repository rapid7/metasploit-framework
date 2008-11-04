#include "precomp.h"

DWORD copy_memory_to_process(HANDLE process, BOOLEAN allocate,
		LPVOID *buffer, DWORD length, DWORD prot);

/*
 * Executes a portion of code in the address space of the supplied process
 * and returns the exit code of the thread that is created
 *
 * FIXME: can-block
 */
DWORD execute_code_stub_in_process(HANDLE process, PVOID buffer, ULONG length,
		LPVOID parameter, DWORD parameterLength, LPDWORD rv)
{
	HANDLE thread = NULL;
	LPVOID paramInProcess = (LPVOID)parameter;
	LPVOID codeInProcess  = (LPVOID)buffer;
	DWORD  threadId;
	DWORD  result = ERROR_SUCCESS;
	DWORD  wait;

	do
	{ 
		// Copy the code and parameter storage
		if ((result = copy_memory_to_process(process, TRUE, &codeInProcess,
				length, PAGE_EXECUTE_READ)) != ERROR_SUCCESS)
			break;
		
		if ((result = copy_memory_to_process(process, TRUE, &paramInProcess,
				parameterLength, PAGE_EXECUTE_READWRITE)) != ERROR_SUCCESS)
			break;

		// Create the thread in the target process
		if (!(thread = CreateRemoteThread(process, NULL, 0, 
				(LPTHREAD_START_ROUTINE)codeInProcess, paramInProcess, 
				0, &threadId)))
		{
			result = GetLastError();
			break;
		}

		// Wait for the thread to terminate
		while ((wait = WaitForSingleObjectEx(thread, 1000, 
				TRUE)) != WAIT_OBJECT_0)
		{
			if (wait == WAIT_FAILED)
			{
				result = GetLastError();
				break;
			}
		}
		
		if (rv)
			GetExitCodeThread(thread, rv);

		// Free the memory in the process
		if ((!VirtualFreeEx(process, codeInProcess, 0, MEM_RELEASE)) ||
		    (!VirtualFreeEx(process, paramInProcess, 0, MEM_RELEASE)))
		{
			result = GetLastError();
			break;
		}
		

	} while (0);

	// Close the thread handle if one was obtained
	if (thread)
		CloseHandle(thread);

	return result;
}

/*
 * Copies memory to the target process, optionally allocating it
 */
DWORD copy_memory_to_process(HANDLE process, BOOLEAN allocate,
		LPVOID *buffer, DWORD length, DWORD prot)
{
	LPVOID remoteBuffer = *buffer;
	DWORD  written;
	DWORD  result = ERROR_SUCCESS;

	do
	{
		if (allocate)
		{
			// Allocate storage for the buffer
			if (!(remoteBuffer = VirtualAllocEx(process, NULL,
					length, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
			{
				result = GetLastError();
				break;
			}
		}

		// Copy the memory from local to remote
		if (!WriteProcessMemory(process, remoteBuffer, 
				*buffer, length, &written))
		{
			result = GetLastError();
			break;
		}

		// Re-protect the region to have the protection mask specified
		if (prot != PAGE_EXECUTE_READWRITE)
		{
			DWORD old;

			if (!VirtualProtectEx(process, remoteBuffer, length,
					prot, &old))
			{
				result = GetLastError();
				break;
			}
		}

	} while (0);

	// Update the buffer pointer
	*buffer = remoteBuffer;

	return result;
}
