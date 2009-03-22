#ifndef _METERPRETER_SOURCE_EXTENSION_INCOGNITO_LIST_TOKENS_H
#define _METERPRETER_SOURCE_EXTENSION_INCOGNITO_LIST_TOKENS_H

// Token struct definitions
typedef struct
{
	char username[256];
	HANDLE token;
} SavedToken;

typedef struct
{
	char username[256];
	int token_num;
	BOOL delegation_available;
	BOOL impersonation_available;
} unique_user_token;

typedef enum
{
	BY_USER,
	BY_GROUP
} TOKEN_ORDER;

SavedToken *get_token_list(DWORD *num_tokens_enum);
void list_unique_tokens(TOKEN_ORDER);
void process_user_token(HANDLE, unique_user_token*, DWORD*, TOKEN_ORDER);

#endif