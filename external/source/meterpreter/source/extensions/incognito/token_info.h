#ifndef _METERPRETER_SOURCE_EXTENSION_INCOGNITO_TOKEN_INFO_H
#define _METERPRETER_SOURCE_EXTENSION_INCOGNITO_TOKEN_INFO_H

BOOL is_delegation_token(HANDLE token);
BOOL is_impersonation_token(HANDLE token);
BOOL is_token(HANDLE token, char *requested_name);
BOOL is_local_system();

BOOL get_domain_username_from_token(HANDLE token, char *full_name_to_return);
BOOL get_domain_groups_from_token(HANDLE token, char **group_name_array[], DWORD *num_groups);
BOOL get_domain_from_token(HANDLE token, char *domain_to_return);

#endif