
/*
 * libloader.h -- misc. defines for libloader
 * Jarkko Turkulainen <jt[at]klake.org>
 *
 */



#include <stdio.h>
#include <windows.h>


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


/* Funtion definitions */

/* kernel32 */
typedef VOID (WINAPI *f_ExitProcess)(UINT);
typedef DWORD (WINAPI *f_LoadLibrary)(LPCTSTR);
typedef FARPROC (WINAPI *f_GetProcAddress)(HMODULE, LPCTSTR);
typedef LPVOID (WINAPI *f_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *f_VirtualFree)(LPVOID, SIZE_T, DWORD);
typedef DWORD (WINAPI *f_VirtualQuery)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef BOOL (WINAPI *f_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI *f_FlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
typedef BOOL (WINAPI *f_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);

/* ntdll */
typedef NTSTATUS (NTAPI *f_NtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *f_NtQueryAttributesFile)(POBJECT_ATTRIBUTES, PFILE_BASIC_INFORMATION);
typedef void (NTAPI *f_NtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, 
		PIO_STATUS_BLOCK, ULONG ShareAccess, ULONG);
typedef NTSTATUS (NTAPI *f_NtCreateSection)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PLARGE_INTEGER,
		ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *f_NtMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG, ULONG,
		PLARGE_INTEGER, PULONG, SECTION_INHERIT, ULONG, ULONG);


/* ws2_32 */
typedef int (WINAPI *f_recv)(SOCKET, char *, int, int);



/* Funtion hashes */

/* kernel32 */
#define	HASH_LoadLibraryA			0xec0e4e8e
#define	HASH_GetProcAddress			0x7c0dfcaa
#define	HASH_ExitProcess			0x73e2d87e
#define HASH_VirtualAlloc			0x91afca54
#define HASH_VirtualFree			0x030633ac
#define HASH_VirtualQuery			0xa3c8c8aa			
#define HASH_VirtualProtect			0x7946c61b
#define HASH_FlushInstructionCache		0x53120980	
#define HASH_WriteProcessMemory			0xd83d6aa1

/* ntdll */
#define HASH_NtOpenSection			0x92b5dd95
#define HASH_NtQueryAttributesFile		0x494a7890
#define HASH_NtOpenFile				0x852974b8
#define HASH_NtCreateSection			0x5bb29bcb
#define HASH_NtMapViewOfSection			0xd5159b94

/* ws2_32 */
#define HASH_recv				0xe71819b6
#define HASH_getpeername			0x95066ef2



typedef struct _SHELLCODE_CTX {

	/* File descriptor */
	SOCKET				sd;
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

	/* function pointers, kernel32 */
	f_LoadLibrary			LoadLibrary;
	f_GetProcAddress		GetProcAddress;
	f_ExitProcess			ExitProcess;
	f_VirtualAlloc			VirtualAlloc;
	f_VirtualFree			VirtualFree;
	f_VirtualQuery			VirtualQuery;
	f_VirtualProtect		VirtualProtect;
	f_FlushInstructionCache		FlushInstructionCache;
	f_WriteProcessMemory		WriteProcessMemory;
	/* function pointers, ntdll */
	f_NtOpenSection			p_NtOpenSection;
	f_NtQueryAttributesFile		p_NtQueryAttributesFile;
	f_NtOpenFile			p_NtOpenFile;
	f_NtCreateSection		p_NtCreateSection;
	f_NtMapViewOfSection		p_NtMapViewOfSection;
	/* function pointers, ws2_32 */
	f_recv				recv;


} SHELLCODE_CTX;


