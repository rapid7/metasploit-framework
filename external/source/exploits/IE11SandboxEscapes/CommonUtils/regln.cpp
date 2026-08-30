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

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include "regln.h"
#include "Utils.h"


int checkargs(int argc, char *argv[]); 
char *win2ntapi(char *win, int len); 
int ntapi_init(void); 
int usage(void); 

static fNtCreateKey NtCreateKey;
static fNtDeleteKey NtDeleteKey;
static fNtSetValueKey NtSetValueKey;

int DeleteLink(LPCWSTR par_src)
{
	DWORD disposition, status;
	HANDLE hdl_nt_keyhandle;
	UNICODE_STRING nt_keyname;
	OBJECT_ATTRIBUTES nt_object_attributes;

	ntapi_init();

	nt_keyname.Buffer = par_src;
	nt_keyname.Length = wcslen(par_src) * sizeof(WCHAR);

	nt_object_attributes.ObjectName = &nt_keyname;
	nt_object_attributes.Attributes = OBJ_CASE_INSENSITIVE | REG_OPTION_OPEN_LINK_ATTR;
	nt_object_attributes.RootDirectory = NULL;   //
	nt_object_attributes.SecurityDescriptor = NULL;   // unused for this object type
	nt_object_attributes.SecurityQualityOfService = NULL;   //
	nt_object_attributes.Length = sizeof(OBJECT_ATTRIBUTES);

	// open link
	status = NtCreateKey(&hdl_nt_keyhandle, KEY_ALL_ACCESS, &nt_object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE, &disposition);

	if (status == 0) {
		DebugPrintf("DEBUG: %ls opened successfully.\n", par_src);

		// delete
		status = NtDeleteKey(hdl_nt_keyhandle);

		if (status == 0) {
			DebugPrintf("DEBUG: %ls deleted successfully.\n", par_src);
		}
		else {
			DebugPrintf("ERROR: Link deletion failed. [Step 2] [Error %08X]\n", status);
			return 1;
		}
	}
	else {
		DebugPrintf("ERROR: Link deletion failed. [Step 1] [Error %08X]\n", status);
		return 1;
	}

	return 0;
};

int CreateLink(LPCWSTR par_src, LPCWSTR par_dst, int opt_volatile)
{
	DWORD disposition, status;
	HANDLE hdl_nt_keyhandle;
	UNICODE_STRING nt_keyname, nt_valuename;
	OBJECT_ATTRIBUTES nt_object_attributes;

	ntapi_init();

	nt_keyname.Buffer = par_src;
	nt_keyname.Length = wcslen(par_src) * sizeof(WCHAR);

	nt_object_attributes.ObjectName = &nt_keyname;
	nt_object_attributes.Attributes = OBJ_CASE_INSENSITIVE;
	nt_object_attributes.RootDirectory = NULL;   //
	nt_object_attributes.SecurityDescriptor = NULL;   // unused for this object type
	nt_object_attributes.SecurityQualityOfService = NULL;   //
	nt_object_attributes.Length = sizeof(OBJECT_ATTRIBUTES);

	// create the key
	if (opt_volatile)
		status = NtCreateKey(&hdl_nt_keyhandle, KEY_ALL_ACCESS, &nt_object_attributes, 0, NULL, REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, &disposition);
	else
		status = NtCreateKey(&hdl_nt_keyhandle, KEY_ALL_ACCESS, &nt_object_attributes, 0, NULL, REG_OPTION_NON_VOLATILE | REG_OPTION_CREATE_LINK, &disposition);

	if (status == 0) {
		DebugPrintf("DEBUG: Key %ls created successfully.\n", par_src);

		// the real action is here:

		nt_valuename.Buffer = REG_LINK_VALUE_NAME;
		nt_valuename.Length = wcslen(REG_LINK_VALUE_NAME) * sizeof(WCHAR);

		status = NtSetValueKey(hdl_nt_keyhandle, &nt_valuename, 0, REG_LINK, par_dst, wcslen(par_dst) * sizeof(WCHAR));

		if (status == 0) {
			DebugPrintf("DEBUG: Value REG_LINK:%ls=%ls set succesfully.\n", REG_LINK_VALUE_NAME, par_dst);
		}
		else {
			DebugPrintf("ERROR: Link creation failed. [Step 2] [Error %08X]\n", status);
			return 1;
		}
	}
	else {
		DebugPrintf("ERROR: Link creation failed. [Step 1] [Error %08X]\n", status);
		return 1;
	}

	return 0;
}


int ntapi_init(void) {
	#ifdef DEBUG
	DebugPrintf("DEBUG: Initializing NTDLL.DLL:NtCreateKey...\n");
	#endif
	if(!(NtCreateKey = (fNtCreateKey) GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateKey" ))) {
		DebugPrintf("This program works only on Windows NT/2000/XP/NET\n");
		return 1;
	}
	#ifdef DEBUG
	DebugPrintf("DEBUG: Initializing NTDLL.DLL:NtDeleteKey...\n");
	#endif
	if(!(NtDeleteKey = (fNtDeleteKey) GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDeleteKey" ))) {
		DebugPrintf("This program works only on Windows NT/2000/XP/NET\n");
		return 1;
	}
	#ifdef DEBUG
	DebugPrintf("DEBUG: Initializing NTDLL.DLL:NtSetValueKey...\n");
	#endif
	if(!(NtSetValueKey = (fNtSetValueKey) GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtSetValueKey" ))) {
		DebugPrintf("This program works only on Windows NT/2000/XP/NET\n");
		return 1;
	}
	return 0;
}

