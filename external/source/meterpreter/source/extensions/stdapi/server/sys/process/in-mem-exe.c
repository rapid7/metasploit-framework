/*
 * Prototype for in-memory executable execution.
 *
 * Improvements that need to be made:
 *
 *    - Support passing arguments to the executable
 *    - General testing with various executables
 *
 * skape
 * mmiller@hick.org
 * 05/09/2005
 */
#include "precomp.h"

#define DUMMY_PROCESS "cmd.exe"

typedef ULONG NTSTATUS;
typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
} PROCESSINFOCLASS;

typedef struct _MINI_PEB
{
	ULONG  Flags;
	LPVOID Mutant;
	LPVOID ImageBaseAddress;
} MINI_PEB, *PMINI_PEB;

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS  ExitStatus;
	PMINI_PEB PebBaseAddress;
	ULONG     AffinityMask;
	ULONG     BasePriority;
	HANDLE    UniqueProcessId;
	HANDLE    InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

LPVOID MapNewExecutableRaw(
		IN LPCSTR ExecutableFilePath);
BOOL MapNewExecutableRegionInProcess(
		IN HANDLE TargetProcessHandle,
		IN HANDLE TargetThreadHandle,
		IN LPVOID NewExecutableRawImage);

int main(
	IN int argc, 
	IN char **argv)
{
	PROCESS_INFORMATION ProcessInformation;
	STARTUPINFO         StartupInformation;
	LPVOID              NewExecutableRawImage = NULL;

	//
	// If we lived without initialization we'd be a conglomerate of chaos and
	// unpredictability...
	//
	ZeroMemory(
			&StartupInformation,
			sizeof(StartupInformation));
	ZeroMemory(
			&ProcessInformation,
			sizeof(ProcessInformation));

	StartupInformation.cb = sizeof(StartupInformation);

	do
	{
		//
		// Yeah...
		//
		if (argc == 1)
		{
			fprintf(stderr, "Usage: %s [executable]\n", 
					argv[0]);

			SetLastError(
					ERROR_INVALID_PARAMETER);
			break;
		}

		//
		// Map in the raw contents of the executable
		//
		if (!(NewExecutableRawImage = MapNewExecutableRaw(
				argv[1])))
		{
			fprintf(stderr, "MapNewExecutableRaw failed, %lu.\n",
					GetLastError());
			break;
		}

		//
		// Run it...
		//
		if (!CreateProcess(
				NULL,
				DUMMY_PROCESS,
				NULL,
				NULL,
				FALSE,
				CREATE_SUSPENDED,
				NULL,
				NULL,
				&StartupInformation,
				&ProcessInformation))
		{
			fprintf(stderr, "CreateProcess(\"%s\") failed, %lu.\n", 
					DUMMY_PROCESS, 
					GetLastError());
			break;
		}

		//
		// Unmap the dummy executable and map in the new executable into the
		// target process
		//
		if (!MapNewExecutableRegionInProcess(
				ProcessInformation.hProcess,
				ProcessInformation.hThread,
				NewExecutableRawImage))
		{
			fprintf(stderr, "MapNewExecutableRegionInProcess failed, %lu.\n",
					GetLastError());
			break;
		}

		//
		// Resume the thread and let it rock...
		//
		if (ResumeThread(
				ProcessInformation.hThread) == (DWORD)-1)
		{
			fprintf(stderr, "ResumeThread failed, %lu.\n",
					GetLastError());
			break;
		}

	} while (0);

	//
	// Cleanup
	//
	if (ProcessInformation.hProcess)
		CloseHandle(
				ProcessInformation.hProcess);
	if (ProcessInformation.hThread)
		CloseHandle(
				ProcessInformation.hThread);

	return GetLastError();
}

//
// Maps the raw contents of the supplied executable image file into the current
// process and returns the address at which the image is mapped.
//
LPVOID MapNewExecutableRaw(
		IN LPCSTR ExecutableFilePath)
{
	HANDLE FileHandle = NULL;
	HANDLE FileMappingHandle = NULL;
	LPVOID NewExecutableRawImage = NULL;

	do
	{
		if ((FileHandle = CreateFile(
				ExecutableFilePath,
				GENERIC_READ,
				FILE_SHARE_READ,
				NULL,
				OPEN_EXISTING,
				FILE_FLAG_RANDOM_ACCESS,
				NULL)) == INVALID_HANDLE_VALUE)
		{
			fprintf(stderr, "CreateFile failed, %lu.\n",
					GetLastError());
			break;
		}

		if (!(FileMappingHandle = CreateFileMapping(
				FileHandle,
				NULL,
				PAGE_READONLY,
				0,
				0,
				NULL)))
		{
			fprintf(stderr, "CreateFileMapping failed, %lu.\n",
					GetLastError());
			break;
		}

		if (!(NewExecutableRawImage = MapViewOfFile(
				FileMappingHandle,
				FILE_MAP_READ,
				0,
				0,
				0)))
		{
			fprintf(stderr, "MapViewOfFile failed, %lu.\n",
					GetLastError());
			break;
		}

	} while (0);

	if (FileMappingHandle)
		CloseHandle(
				FileMappingHandle);
	if (FileHandle)
		CloseHandle(
				FileHandle);

	return NewExecutableRawImage;
}

//
// Maps the contents of the executable image into the new process and unmaps
// the original executable.  All necessary fixups are performed to allow the
// transfer of execution control the new executable in a seamless fashion.
//
BOOL MapNewExecutableRegionInProcess(
		IN HANDLE TargetProcessHandle,
		IN HANDLE TargetThreadHandle,
		IN LPVOID NewExecutableRawImage)
{
	PROCESS_BASIC_INFORMATION BasicInformation;
	PIMAGE_SECTION_HEADER     SectionHeader;
	PIMAGE_DOS_HEADER         DosHeader;
	PIMAGE_NT_HEADERS         NtHeader;
	PMINI_PEB                 ProcessPeb;
	NTSTATUS                  (NTAPI *NtUnmapViewOfSection)(HANDLE, LPVOID) = NULL;
	NTSTATUS                  (NTAPI *NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, LPVOID, ULONG, PULONG) = NULL;
	NTSTATUS                  Status;
	CONTEXT                   ThreadContext;
	LPVOID                    OldEntryPoint = NULL;
	LPVOID                    TargetImageBase = NULL;
	ULONG                     SectionIndex = 0;
	ULONG                     SizeOfBasicInformation;
	BOOL                      Success = FALSE;

	//
	// Error checking? Bah.
	//
	DosHeader = (PIMAGE_DOS_HEADER)NewExecutableRawImage;
	NtHeader  = (PIMAGE_NT_HEADERS)((PCHAR)NewExecutableRawImage + DosHeader->e_lfanew);

	do
	{
		//
		// Get the old entry point address by inspecting eax of the current
		// thread (which should be BaseProcessStart).  Eax holds the address
		// of the entry point for the executable when the process is created
		// suspended.
		//
		ZeroMemory(
				&ThreadContext,
				sizeof(ThreadContext));

		ThreadContext.ContextFlags = CONTEXT_INTEGER;

		if (!GetThreadContext(
				TargetThreadHandle,
				&ThreadContext))
		{
			fprintf(stderr, "GetThreadContext failed, %lu.\n",
					GetLastError());
			break;
		}

		OldEntryPoint = (LPVOID)ThreadContext.Eax;

		//
		// Unmap the old executable region in the child process to avoid 
		// conflicts
		//
		NtUnmapViewOfSection = (NTSTATUS (NTAPI *)(HANDLE, LPVOID))GetProcAddress(
				GetModuleHandle(
					TEXT("NTDLL")),
				"NtUnmapViewOfSection");

		if ((Status = NtUnmapViewOfSection(
				TargetProcessHandle,
				OldEntryPoint)) != ERROR_SUCCESS)
		{
			fprintf(stderr, "NtUnmapViewOfSection failed, %.8x.\n",
					Status);

			SetLastError(ERROR_INVALID_ADDRESS);
			break;
		}

		//
		// Change the entry point address to the new executable's entry point
		//
		ThreadContext.Eax = NtHeader->OptionalHeader.AddressOfEntryPoint + 
					NtHeader->OptionalHeader.ImageBase;

		if (!SetThreadContext(
				TargetThreadHandle,
				&ThreadContext))
		{
			fprintf(stderr, "SetThreadContext failed, %lu.\n",
					GetLastError());
			break;
		}
		
		//
		// Allocate storage for the new executable in the child process
		//
		if (!(TargetImageBase = VirtualAllocEx(
				TargetProcessHandle,
				(LPVOID)NtHeader->OptionalHeader.ImageBase,
				NtHeader->OptionalHeader.SizeOfImage,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE)))
		{
			fprintf(stderr, "VirtualAllocEx failed, %lu.\n",
					GetLastError());
			break;
		}

		//
		// Update the executable's image base address in the PEB...
		//
		NtQueryInformationProcess = (NTSTATUS (NTAPI *)(HANDLE, PROCESSINFOCLASS, LPVOID, ULONG, PULONG))GetProcAddress(
				GetModuleHandle(
					TEXT("NTDLL")),
				"NtQueryInformationProcess");

		if (NtQueryInformationProcess(
				TargetProcessHandle,
				ProcessBasicInformation,
				&BasicInformation,
				sizeof(BasicInformation),
				&SizeOfBasicInformation) != ERROR_SUCCESS)
		{
			fprintf(stderr, "NtQueryInformationProcess failed, %lu.\n",
					GetLastError());
			break;
		}

		ProcessPeb = BasicInformation.PebBaseAddress;

		if (!WriteProcessMemory(
				TargetProcessHandle,
				(LPVOID)&ProcessPeb->ImageBaseAddress,
				(LPVOID)&NtHeader->OptionalHeader.ImageBase,
				sizeof(LPVOID),
				NULL))
		{
			fprintf(stderr, "WriteProcessMemory(ImageBaseAddress) failed, %lu.\n",
					GetLastError());
			break;
		}

		//
		// Copy the image headers and all of the section contents
		//
		if (!WriteProcessMemory(
				TargetProcessHandle,
				TargetImageBase,
				NewExecutableRawImage,
				NtHeader->OptionalHeader.SizeOfHeaders,
				NULL))
		{
			fprintf(stderr, "WriteProcessMemory(Headers) failed, %lu.\n",
					GetLastError());
			break;
		}

		Success = TRUE;

		for (SectionIndex = 0, 
		      SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
		     SectionIndex < NtHeader->FileHeader.NumberOfSections;
		     SectionIndex++)
		{
			if (!WriteProcessMemory(
					TargetProcessHandle,
					(LPVOID)((PCHAR)TargetImageBase + 
							SectionHeader[SectionIndex].VirtualAddress),
					(LPVOID)((PCHAR)NewExecutableRawImage +
							SectionHeader[SectionIndex].PointerToRawData),
					SectionHeader[SectionIndex].SizeOfRawData,
					NULL))
			{
				fprintf(stderr, "WriteProcessMemory(Section) failed, %lu.\n",
						GetLastError());

				Success = FALSE;
				break;
			}
		}

	} while (0);

	return Success;
}
