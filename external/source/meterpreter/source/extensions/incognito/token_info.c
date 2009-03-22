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
#include "incognito.h"

BOOL get_domain_from_token(HANDLE token, char *domain_to_return)
{
	LPVOID TokenUserInfo[BUF_SIZE];
	char username[BUF_SIZE] = "", domainname[BUF_SIZE] = "";
	DWORD user_length = sizeof(username), domain_length = sizeof(domainname), sid_type = 0, returned_tokinfo_length;

	if (!GetTokenInformation(token, TokenUser, TokenUserInfo, BUF_SIZE, &returned_tokinfo_length))
		return FALSE;
	LookupAccountSidA(NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username, &user_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type);

	strcpy(domain_to_return, domainname);

	return TRUE;
}

BOOL get_domain_username_from_token(HANDLE token, char *full_name_to_return)
{
	LPVOID TokenUserInfo[BUF_SIZE];
	char username[BUF_SIZE] = "", domainname[BUF_SIZE] = "";
	DWORD user_length = sizeof(username), domain_length = sizeof(domainname), sid_type = 0, returned_tokinfo_length;

	if (!GetTokenInformation(token, TokenUser, TokenUserInfo, BUF_SIZE, &returned_tokinfo_length))
		return FALSE;
	LookupAccountSidA(NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username, &user_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type);

 	// Make full name in DOMAIN\USERNAME format
	sprintf(full_name_to_return, "%s\\%s", domainname, username);

	return TRUE;
}

BOOL get_domain_groups_from_token(HANDLE token, char **group_name_array[], DWORD *num_groups)
{
	LPVOID TokenGroupsInfo[BUF_SIZE];
	char groupname[BUF_SIZE] = "", domainname[BUF_SIZE] = "";
	DWORD i, group_length = sizeof(groupname), domain_length = sizeof(domainname), sid_type = 0, returned_tokinfo_length;

	if (!GetTokenInformation(token, TokenGroups, TokenGroupsInfo, BUF_SIZE, &returned_tokinfo_length))
		return FALSE;
	*group_name_array = (char**)calloc(((TOKEN_GROUPS*)TokenGroupsInfo)->GroupCount, sizeof(char*));
	*num_groups = ((TOKEN_GROUPS*)TokenGroupsInfo)->GroupCount;

	for (i=0;i<*num_groups;i++)
	{
		LookupAccountSidA(NULL, ((TOKEN_GROUPS*)TokenGroupsInfo)->Groups[i].Sid, groupname, &group_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type);
		(*group_name_array)[i] = (char*)calloc(BUF_SIZE, sizeof(char));
		// Make full name in DOMAIN\GROUPNAME format
		sprintf((*group_name_array)[i], "%s\\%s", domainname, groupname);
	} 	

	return TRUE;
}

BOOL is_delegation_token(HANDLE token)
{
	HANDLE temp_token;
	BOOL ret;
	LPVOID TokenImpersonationInfo[BUF_SIZE];
	DWORD returned_tokinfo_length;

	if (GetTokenInformation(token, TokenImpersonationLevel, TokenImpersonationInfo, BUF_SIZE, &returned_tokinfo_length))
	if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInfo) == SecurityDelegation)
		return TRUE;
	else
		return FALSE;

	ret = DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenImpersonation, &temp_token);
	CloseHandle(temp_token);
	return ret;
}

BOOL is_impersonation_token(HANDLE token)
{
	HANDLE temp_token;
	BOOL ret;
	LPVOID TokenImpersonationInfo[BUF_SIZE];
	DWORD returned_tokinfo_length;

	if (GetTokenInformation(token, TokenImpersonationLevel, TokenImpersonationInfo, BUF_SIZE, &returned_tokinfo_length))
	if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInfo) >= SecurityImpersonation)
		return TRUE;
	else
		return FALSE;

	ret = DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &temp_token);
	CloseHandle(temp_token);
	return ret;
}

BOOL is_token(HANDLE token, char *requested_name)
{	
	DWORD i, num_groups=0;
	char *full_name, **group_name_array = NULL;
	BOOL ret = FALSE;

	// If token is NULL then return
	if (!token)
		return FALSE;

	full_name = calloc(BUF_SIZE, sizeof(char));
	get_domain_username_from_token(token, full_name);
	if (!_stricmp(requested_name, full_name))
		ret = TRUE;

	get_domain_groups_from_token(token, &group_name_array, &num_groups);
	
	for (i=0;i<num_groups;i++)
	{
		if (!_stricmp(requested_name, group_name_array[i]))
			ret = TRUE;
		free(group_name_array[i]);
	}

	// Cleanup
	free(group_name_array);
	free(full_name);

	return ret;
}

BOOL is_local_system()
{
	HANDLE token;
	char full_name[BUF_SIZE];

	// If there is a thread token use that, otherwise use current process token
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &token))
		OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token);
	
	get_domain_username_from_token(token, full_name);
	CloseHandle(token);

	if (!_stricmp("NT AUTHORITY\\SYSTEM", full_name))
		return TRUE;
	else
		return FALSE;
}