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
#ifdef _WIN64
//
// based on MemExec64 source by steve10120 [at] ic0de.org
//	clever method of getting contextinformation for entry point data, x64 doesnt give us ThreadContext.Eax
// adaptation for in-mem-exe.c by RageLtMan
// TODO: add wow64 launcher, add src/target image arch checks
//
BOOL MapNewExecutableRegionInProcess(
		IN HANDLE TargetProcessHandle,
		IN HANDLE TargetThreadHandle,
		IN LPVOID NewExecutableRawImage);

typedef LONG (WINAPI * NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

DWORD_PTR Align(DWORD_PTR Value, DWORD_PTR Alignment)
{
    DWORD_PTR dwResult = Value;

    if (Alignment > 0)
    {
        if ((Value % Alignment) > 0)
            dwResult = (Value + Alignment) - (Value % Alignment);
    }
    return dwResult;
}

BOOL MapNewExecutableRegionInProcess(
		IN HANDLE TargetProcessHandle,
		IN HANDLE TargetThreadHandle,
		IN LPVOID NewExecutableRawImage)
{ 
	PROCESS_INFORMATION       BasicInformation;
	PIMAGE_SECTION_HEADER     SectionHeader;
	PIMAGE_DOS_HEADER         DosHeader;
	PIMAGE_NT_HEADERS         NtHeader64;
	DWORD_PTR                 dwImageBase;
    NtUnmapViewOfSection      pNtUnmapViewOfSection;
    LPVOID                    pImageBase;
    SIZE_T                    dwBytesWritten;
    SIZE_T                    dwBytesRead;
    int                       Count;
	PCONTEXT                  ThreadContext;
	BOOL                      Success = FALSE;

	DosHeader = (PIMAGE_DOS_HEADER)NewExecutableRawImage;
    if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE)
    {
        NtHeader64 = (PIMAGE_NT_HEADERS64)((DWORD)NewExecutableRawImage + DosHeader->e_lfanew);
        if (NtHeader64->Signature == IMAGE_NT_SIGNATURE)
        {
            RtlZeroMemory(&BasicInformation, sizeof(PROCESS_INFORMATION));
            ThreadContext = (PCONTEXT)VirtualAlloc(NULL, sizeof(ThreadContext) + 4, MEM_COMMIT, PAGE_READWRITE);
            ThreadContext = (PCONTEXT)Align((DWORD)ThreadContext, 4);
            ThreadContext->ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(TargetThreadHandle, ThreadContext)) //used to be LPCONTEXT(ThreadContext)
            {
                ReadProcessMemory(TargetProcessHandle, (LPCVOID)(ThreadContext->Rdx + 16), &dwImageBase, sizeof(DWORD_PTR), &dwBytesRead);

                pNtUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
                if (pNtUnmapViewOfSection)
                    pNtUnmapViewOfSection(TargetProcessHandle, (PVOID)dwImageBase);

                pImageBase = VirtualAllocEx(TargetProcessHandle, (LPVOID)NtHeader64->OptionalHeader.ImageBase, NtHeader64->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);
                if (pImageBase)
                {
                    WriteProcessMemory(TargetProcessHandle, pImageBase, (LPCVOID)NewExecutableRawImage, NtHeader64->OptionalHeader.SizeOfHeaders, &dwBytesWritten);
                    SectionHeader = IMAGE_FIRST_SECTION(NtHeader64);
                    for (Count = 0; Count < NtHeader64->FileHeader.NumberOfSections; Count++)
                    {
                        WriteProcessMemory(TargetProcessHandle, (LPVOID)((DWORD_PTR)pImageBase + SectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)NewExecutableRawImage + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, &dwBytesWritten);     
                        SectionHeader++;
                    }
                    WriteProcessMemory(TargetProcessHandle, (LPVOID)(ThreadContext->Rdx + 16), (LPVOID)&NtHeader64->OptionalHeader.ImageBase, sizeof(DWORD_PTR), &dwBytesWritten);
                    ThreadContext->Rcx = (DWORD_PTR)pImageBase + NtHeader64->OptionalHeader.AddressOfEntryPoint;
                    SetThreadContext(TargetThreadHandle, (LPCONTEXT)ThreadContext);
                    ResumeThread(TargetThreadHandle);
					Success = TRUE;
                }
                else
                    TerminateProcess(TargetProcessHandle, 0);
            VirtualFree(ThreadContext, 0, MEM_RELEASE);
            }
        }
    }

	return Success;
}

#else
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
			//
			// Skip uninitialized data
			//
			if ((!SectionHeader[SectionIndex].SizeOfRawData) ||
			    (SectionHeader[SectionIndex].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA))
				continue;

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

#endif