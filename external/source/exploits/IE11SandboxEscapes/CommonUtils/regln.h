/*--------------------------------------------------------------------
REGLN - Manage Windows Rregistry Links                           V20R0
======================================================================
            Antoni Sawicki <as@ntinternals.net>; Dublin, July 10 2005;

  The following Copyrights apply:

    Copyright (c) 1998-2005 by Antoni Sawicki  <as@ntinternals.net>
    Copyright (c) 1998-2005 by Tomasz Nowak <tommy@ntinternals.net>
    Copyright (c) 1998 by Mark Russinovich  <mark@sysinternals.com>

  License:

  This software is distributed under the terms  and  conditions  of
  GPL  - GNU  General  Public  License. The software is provided AS
  IS and ABSOLUTELY NO WARRANTY IS  GIVEN.  The  author  takes   no
  responsibility for any damages or consequences  of  usage of this 
  software. For more information, please read the attached GPL.TXT.

--------------------------------------------------------------------*/



#define REG_LINK_VALUE_NAME    L"SymbolicLinkValue" // found by tenox
//#define REG_OPTION_CREATE_LINK 2 // this is defined in MSVC 2.0 but not after
#define REG_OPTION_OPEN_LINK_ATTR   0x100 // found by tommy
#define OBJ_CASE_INSENSITIVE   0x40

//
// Following definitions are generously provided by Mark Russinovitch
//
typedef struct _UNICODE_STRING {
	WORD Length;
	WORD MaximumLength;
	PCWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	DWORD Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	DWORD Attributes;
	PVOID SecurityDescriptor; 
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef DWORD (__stdcall *fNtCreateKey)(
	HANDLE KeyHandle, 
	DWORD DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes,
	DWORD TitleIndex, 
	PUNICODE_STRING Class, 
	DWORD CreateOptions, 
	PDWORD Disposition 
);

typedef DWORD (__stdcall *fNtSetValueKey)(
	HANDLE  KeyHandle,
	PUNICODE_STRING  ValueName,
	DWORD  TitleIndex,
	DWORD  Type,
	const void*  Data,
	DWORD  DataSize
);

typedef DWORD (__stdcall *fNtDeleteKey)(
	HANDLE KeyHandle
);
