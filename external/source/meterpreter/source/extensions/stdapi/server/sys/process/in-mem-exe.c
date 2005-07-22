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

BOOL MapNewExecutableRegionInProcess(
		IN HANDLE TargetProcessHandle,
		IN HANDLE TargetThreadHandle,
		IN LPVOID NewExecutableRawImage);

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
			break;
		
		//
		// Allocate storage for the new executable in the child process
		//
		if (!(TargetImageBase = VirtualAllocEx(
				TargetProcessHandle,
				(LPVOID)NtHeader->OptionalHeader.ImageBase,
				NtHeader->OptionalHeader.SizeOfImage,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE)))
			break;

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
			break;

		ProcessPeb = BasicInformation.PebBaseAddress;

		if (!WriteProcessMemory(
				TargetProcessHandle,
				(LPVOID)&ProcessPeb->ImageBaseAddress,
				(LPVOID)&NtHeader->OptionalHeader.ImageBase,
				sizeof(LPVOID),
				NULL))
			break;

		//
		// Copy the image headers and all of the section contents
		//
		if (!WriteProcessMemory(
				TargetProcessHandle,
				TargetImageBase,
				NewExecutableRawImage,
				NtHeader->OptionalHeader.SizeOfHeaders,
				NULL))
			break;

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
				Success = FALSE;
				break;
			}
		}

	} while (0);

	return Success;
}
