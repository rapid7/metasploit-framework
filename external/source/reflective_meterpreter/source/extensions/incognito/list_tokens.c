#define _CRT_SECURE_NO_DEPRECATE 1
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <aclapi.h>
#include <accctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <lm.h>
#include <wchar.h>
#include "list_tokens.h"
#include "token_info.h"
#include "incognito.h"


typedef LONG   NTSTATUS;
typedef VOID   *POBJECT;

typedef enum _OBJECT_INFORMATION_CLASS{
   ObjectBasicInformation,
      ObjectNameInformation,
      ObjectTypeInformation,
      ObjectAllTypesInformation,
      ObjectHandleInformation
} OBJECT_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE {
   ULONG           uIdProcess;
   UCHAR           ObjectType;
   UCHAR           Flags;
   USHORT          Handle;
   POBJECT         pObject;
   ACCESS_MASK     GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
   ULONG                   uCount;
   SYSTEM_HANDLE   Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _UNICODE_STRING {
   USHORT Length;
   USHORT MaximumLength;
   PWSTR  Buffer;
} UNICODE_STRING;

#define STATUS_SUCCESS                          ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH             ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW                  ((NTSTATUS)0x80000005L)
#define SystemHandleInformation                 16

typedef NTSTATUS (WINAPI *NTQUERYSYSTEMINFORMATION)(DWORD SystemInformationClass, 
                                                    PVOID SystemInformation,
                                                    DWORD SystemInformationLength, 
                                                    PDWORD ReturnLength);

typedef NTSTATUS (WINAPI *NTQUERYOBJECT)(HANDLE ObjectHandle, 
                                         OBJECT_INFORMATION_CLASS ObjectInformationClass, 
                                         PVOID ObjectInformation,
                                         DWORD Length, 
                                         PDWORD ResultLength);

NTQUERYOBJECT              NtQueryObject ;
NTQUERYSYSTEMINFORMATION   NtQuerySystemInformation; 

LPWSTR         GetObjectInfo(HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass);

typedef UNICODE_STRING OBJECT_NAME_INFORMATION;
typedef UNICODE_STRING *POBJECT_NAME_INFORMATION;

LPWSTR GetObjectInfo(HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass)
{
   LPWSTR data = NULL;
   DWORD dwSize = sizeof(OBJECT_NAME_INFORMATION);
   POBJECT_NAME_INFORMATION pObjectInfo = (POBJECT_NAME_INFORMATION) malloc(dwSize);
   
   NTSTATUS ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);   
   if((ntReturn == STATUS_BUFFER_OVERFLOW) || (ntReturn == STATUS_INFO_LENGTH_MISMATCH)){
      pObjectInfo =realloc(pObjectInfo ,dwSize);
      ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
   }
   if((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->Buffer != NULL))
   {
      data = (LPWSTR) calloc(pObjectInfo->Length, sizeof(WCHAR));
      CopyMemory(data, pObjectInfo->Buffer, pObjectInfo->Length);
   }
   free(pObjectInfo);
   return data;
}

SavedToken *get_token_list(DWORD *num_tokens_enum)
{
	DWORD total=0, i, num_tokens=0, token_list_size = BUF_SIZE, dwSize = sizeof(SYSTEM_HANDLE_INFORMATION);
	HANDLE process;
	PSYSTEM_HANDLE_INFORMATION pHandleInfo;
	NTSTATUS ntReturn;
	SavedToken *token_list = (SavedToken*)calloc(token_list_size, sizeof(SavedToken)); 

	NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQuerySystemInformation");
	NtQueryObject= (NTQUERYOBJECT)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQueryObject");

	pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(dwSize);
	ntReturn = NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, dwSize, &dwSize);
   
	if(ntReturn == STATUS_INFO_LENGTH_MISMATCH){
		free(pHandleInfo);
		pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(dwSize);
		ntReturn = NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, dwSize, &dwSize);
	}

	*num_tokens_enum = 0;

	if(ntReturn == STATUS_SUCCESS)
	{
		for(i = 0; i < pHandleInfo->uCount; i++)
		{          
			process = OpenProcess(MAXIMUM_ALLOWED,FALSE, pHandleInfo->Handles[i].uIdProcess);   
			if(process != INVALID_HANDLE_VALUE)
			{
				HANDLE hObject = NULL;
				if(DuplicateHandle(process, (HANDLE)pHandleInfo->Handles[i].Handle,
					GetCurrentProcess(), &hObject, MAXIMUM_ALLOWED, FALSE, 0x02) != FALSE)                  
				{
					LPWSTR lpwsType=NULL ;              
					lpwsType = GetObjectInfo(hObject, ObjectTypeInformation);
					
					if ((lpwsType!=NULL) && !wcscmp(lpwsType, L"Token") )
					{
						// Reallocate space if necessary
						if(*num_tokens_enum >= token_list_size)
						{
							token_list_size *= 2;
							token_list = (SavedToken*)realloc(token_list, token_list_size*sizeof(SavedToken));
							if (!token_list)
								goto cleanup;
						}
						token_list[*num_tokens_enum].token = hObject;
						get_domain_username_from_token(hObject, token_list[*num_tokens_enum].username);
						(*num_tokens_enum)++;
					}
					else
						CloseHandle(hObject);
				}
				CloseHandle(process);
			}
		}
	}

cleanup:
	free(pHandleInfo);

	return token_list;
}

void process_user_token(HANDLE token, unique_user_token *uniq_tokens, DWORD *num_tokens, TOKEN_ORDER token_order)
{
	DWORD i, j, num_groups=0;
	char *full_name, **group_name_array = NULL;
	BOOL user_exists = FALSE;

	// If token is NULL then return
	if (!token)
		return;

	// Get token user or groups
	if (token_order == BY_USER)
	{
		full_name = calloc(BUF_SIZE, sizeof(char));
		num_groups = 1;
		if (!get_domain_username_from_token(token, full_name))
			goto cleanup;
	}
	else if (token_order == BY_GROUP)
		if (!get_domain_groups_from_token(token, &group_name_array, &num_groups))
			goto cleanup;
	
	for (i=0;i<num_groups;i++)
	{
		if (token_order == BY_GROUP)
			full_name = (char*)group_name_array[i];

		// Check
		if (!_stricmp("None", strchr(full_name, '\\') + 1) || !_stricmp("Everyone", strchr(full_name, '\\') + 1)
			|| !_stricmp("LOCAL", strchr(full_name, '\\') + 1) || !_stricmp("NULL SID", strchr(full_name, '\\') + 1))
			continue;

		// Check to see if username has been seen before
		for (j=0;j<*num_tokens;j++)
		{
			// If found then increment the number and set delegation flag if appropriate
			if (!_stricmp(uniq_tokens[j].username, full_name))
			{
				uniq_tokens[j].token_num++;
				user_exists = TRUE;
				if (is_delegation_token(token))
					uniq_tokens[j].delegation_available = TRUE;
				if (is_impersonation_token(token))
					uniq_tokens[j].impersonation_available = TRUE;
				break;
			}
		}

		// If token user has not been seen yet then create new entry
		if (!user_exists)
		{
			strcpy(uniq_tokens[*num_tokens].username, full_name);
			uniq_tokens[*num_tokens].token_num = 1;
			uniq_tokens[*num_tokens].delegation_available = FALSE;
			uniq_tokens[*num_tokens].impersonation_available = FALSE;

			if (is_delegation_token(token))
				uniq_tokens[*num_tokens].delegation_available = TRUE;
			if (is_impersonation_token(token))
				uniq_tokens[*num_tokens].impersonation_available = TRUE;

			(*num_tokens)++;
		}
		else
			user_exists = FALSE;

		// Cleanup
		if (token_order == BY_GROUP && group_name_array[i])
			free(group_name_array[i]);
	}

	// Cleanup
cleanup:
	if (token_order == BY_GROUP && group_name_array)
		free(group_name_array);
	else if (token_order == BY_USER && full_name)
		free(full_name);
}
