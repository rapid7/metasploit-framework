#pragma once

#include <Windows.h>
#include <winternl.h>

#define DIRECTORY_QUERY 0x0001
#define DIRECTORY_TRAVERSE 0x0002
#define DIRECTORY_CREATE_OBJECT 0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY 0x0008
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

typedef NTSTATUS(NTAPI *_NtCreateDirectoryObject)(PHANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(NTAPI *_NtCreateDirectoryObjectEx)(PHANDLE Handle, ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ShadowDir, BOOLEAN Something);
typedef NTSTATUS(NTAPI *_NtOpenDirectoryObject)(PHANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef VOID(NTAPI *_RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

typedef NTSTATUS(NTAPI* _NtCreateSymbolicLinkObject)(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING TargetName);
typedef NTSTATUS(NTAPI* _NtOpenSymbolicLinkObject)(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(NTAPI* _NtQuerySymbolicLinkObject)(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength);
typedef NTSTATUS(NTAPI* _NtOpenFile)(
	_Out_ PHANDLE            FileHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK   IoStatusBlock,
	_In_  ULONG              ShareAccess,
	_In_  ULONG              OpenOptions
	);

const ULONG FileLinkInformation = 11;

typedef struct _FILE_LINK_INFORMATION {
	BOOLEAN ReplaceIfExists;
	HANDLE  RootDirectory;
	ULONG   FileNameLength;
	WCHAR   FileName[1];
} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;

typedef NTSTATUS(__stdcall *_ZwSetInformationFile)(
	_In_   HANDLE                 FileHandle,
	_Out_  PIO_STATUS_BLOCK       IoStatusBlock,
	_In_   PVOID                  FileInformation,
	_In_   ULONG                  Length,
	_In_   ULONG			      FileInformationClass
	);
typedef ULONG(NTAPI* _RtlNtStatusToDosError)(NTSTATUS status);
void SetNtLastError(NTSTATUS status);

#define DEFINE_NTDLL(x) _ ## x f ## x = (_ ## x)GetProcAddressNT(#x)
