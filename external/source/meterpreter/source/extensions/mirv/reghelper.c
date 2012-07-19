// QueryKey.cpp : Defines the entry point for the console application.
//

#include "mirv.h"

// QueryKey - Enumerates the subkeys of key and its associated values.
//     hKey - Key whose subkeys and values are to be enumerated.

#include <windows.h>
#include <stdio.h>


//
//#define MAX_KEY_LENGTH 255
//#define MAX_VALUE_NAME 16383
//#define MAX_VALUE_DATA 65535
//
//typedef struct messageProviders_struct {
//	TCHAR* providerNameBestGuess;
//	TCHAR* CategoryMessageFile;
//	TCHAR* EventMessageFile;
//	TCHAR* ParameterMessageFile;
//} messageProvider;
//
//
//typedef struct node_struct {
//	messageProvider mp;
//	struct node_struct *next;
//} node;
//
//typedef node* pnode;


int QueryKey(char *currentRoot,messageProvider **mpArray,int mpIndex) 
{ 
	char     achKey[MAX_KEY_LENGTH];   // buffer for subkey name
	DWORD    cbName;                   // size of name string 
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
	DWORD    cchClassName = MAX_PATH;  // size of class string 
	DWORD    cSubKeys=0;               // number of subkeys 
	DWORD    cbMaxSubKey;              // longest subkey size 
	DWORD    cchMaxClass;              // longest class string 
	DWORD    cValues;              // number of values for key 
	DWORD    cchMaxValue;          // longest value name 
	DWORD    cbMaxValueData;       // longest value data 
	DWORD    cbSecurityDescriptor; // size of security descriptor 
	FILETIME ftLastWriteTime;      // last write time 

	DWORD i, retCode; 

	char  achValue[MAX_VALUE_NAME]; 
	DWORD cchValue = MAX_VALUE_NAME; 

	HKEY hKey;
	// POST C++

	messageProvider *mp;
	BOOL anyGoodValues=FALSE;
	char newRoot[2048];
	//_tprintf(_T("Entering %s\n"), currentRoot);

	if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,currentRoot,0,KEY_READ,&hKey) == ERROR_SUCCESS){




		// Get the class name and the value count. 
		retCode = RegQueryInfoKey(
			hKey,                    // key handle 
			achClass,                // buffer for class name 
			&cchClassName,           // size of class string 
			NULL,                    // reserved 
			&cSubKeys,               // number of subkeys 
			&cbMaxSubKey,            // longest subkey size 
			&cchMaxClass,            // longest class string 
			&cValues,                // number of values for this key 
			&cchMaxValue,            // longest value name 
			&cbMaxValueData,         // longest value data 
			&cbSecurityDescriptor,   // security descriptor 
			&ftLastWriteTime);       // last write time 

		// Enumerate the subkeys, until RegEnumKeyEx fails.

		if (cSubKeys)
		{
			//printf( "\nNumber of subkeys: %d\n", cSubKeys);

			for (i=0; i<cSubKeys; i++) 
			{ 
				cbName = MAX_KEY_LENGTH;
				retCode = RegEnumKeyEx(hKey, i,
					achKey, 
					&cbName, 
					NULL, 
					NULL, 
					NULL, 
					&ftLastWriteTime); 
				if (retCode == ERROR_SUCCESS) 
				{
				//	_tprintf(TEXT("(%d) %s\n"), i+1, achKey);
					//TCHAR 
					int size=sizeof(newRoot);
			//		_tprintf(_T("Current key: %s\n"),achKey);
					sprintf_s(newRoot,size,"%s\\%s",currentRoot,achKey);
					mpIndex=QueryKey(newRoot,mpArray,mpIndex); 


				}
			}
		} 

		// Enumerate the key values. 

		if (cValues) 
		{
		//	printf( "\nNumber of values: %d\n", cValues);
			LPBYTE data;			
			DWORD size;
			data=(LPBYTE) malloc(MAX_VALUE_DATA);//FIXME
			mp=(messageProvider *)malloc(sizeof(messageProvider));
			ZeroMemory(mp,sizeof(messageProvider));
			mp->providerNameBestGuess=_strdup(currentRoot);//{(TCHAR*) currentRoot,NULL,NULL,NULL};
			
			for (i=0, retCode=ERROR_SUCCESS; i<cValues; i++) 
			{ 
				cchValue = MAX_VALUE_NAME; 
				achValue[0] = '\0'; 
				ZeroMemory(data,MAX_VALUE_DATA);
				//data=(LPBYTE) malloc(MAX_VALUE_DATA);
				size=MAX_VALUE_DATA;
				retCode = RegEnumValue(hKey, i, 
					achValue, 
					&cchValue, 
					NULL, 
					NULL,
					data,
					&size);

				if (retCode == ERROR_SUCCESS ) 
				{ 
		//			_tprintf(TEXT("(%d) '%s'\n"), i+1, achValue); 
					BOOL valFound=FALSE;
					if (strcmp(achValue,"ParameterMessageFile") == 0 ){

						mp->ParameterMessageFile=_strdup((char *)data);
						anyGoodValues=TRUE;
						//valFound=TRUE;
					}
					if (strcmp(achValue,"CategoryMessageFile") == 0 ){

						mp->CategoryMessageFile=_strdup((char *)data);
						anyGoodValues=TRUE;
						//valFound=TRUE;
					}
					if (strcmp(achValue,"EventMessageFile") == 0 ){
						mp->ParameterMessageFile=_strdup((char *)data);		
						anyGoodValues=TRUE;
						//valFound=TRUE;
					}
					//if(!valFound){
					//	//FIXME:
					//}
				}

			}
			free(data);
			if(anyGoodValues)				
				mpArray[mpIndex++]=mp;		
		}


		RegCloseKey(hKey);
	}

	return mpIndex;
}


int getProviders(messageProvider **mpArray){
	//messageProvider mpArray[MAX_RESOURCES];
	int mpIndex =0;
	mpIndex=QueryKey("SYSTEM\\CurrentControlSet\\services\\eventlog",mpArray,mpIndex);
	return mpIndex;

}
//void __cdecl _tmain(void)
//{
//	messageProvider mpArray[1024];
//	int mpIndex =0;
//	QueryKey(_T("SYSTEM\\CurrentControlSet\\services\\eventlog\\Application"),mpArray,mpIndex);
//	return;
//}

unsigned int getEventLogProviders(char **providers){
	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
	DWORD    cbName;                   // size of name string 
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
	DWORD    cchClassName = MAX_PATH;  // size of class string 
	DWORD    cSubKeys=0;               // number of subkeys 
	DWORD    cbMaxSubKey;              // longest subkey size 
	DWORD    cchMaxClass;              // longest class string 
	DWORD    cValues;              // number of values for key 
	DWORD    cchMaxValue;          // longest value name 
	DWORD    cbMaxValueData;       // longest value data 
	DWORD    cbSecurityDescriptor; // size of security descriptor 
	FILETIME ftLastWriteTime;      // last write time 
	
	DWORD i, retCode; 
	size_t origsize,convertedChars=0;
//	TCHAR  achValue[MAX_VALUE_NAME]; 
	DWORD cchValue = MAX_VALUE_NAME; 

	HKEY hKey;
//	char nstring[1024];
	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\services\\eventlog\\",0,KEY_READ,&hKey) == ERROR_SUCCESS){




		// Get the class name and the value count. 
		retCode = RegQueryInfoKey(
			hKey,                    // key handle 
			achClass,                // buffer for class name 
			&cchClassName,           // size of class string 
			NULL,                    // reserved 
			&cSubKeys,               // number of subkeys 
			&cbMaxSubKey,            // longest subkey size 
			&cchMaxClass,            // longest class string 
			&cValues,                // number of values for this key 
			&cchMaxValue,            // longest value name 
			&cbMaxValueData,         // longest value data 
			&cbSecurityDescriptor,   // security descriptor 
			&ftLastWriteTime);       // last write time 



		if (cSubKeys)
		{
			providers=(char **) malloc(sizeof(char *)*cSubKeys);
			ZeroMemory(providers,sizeof(char *)*cSubKeys);
			for (i=0; i<cSubKeys; i++) 
			{ 
				cbName = MAX_KEY_LENGTH;
				retCode = RegEnumKeyEx(hKey, i,
					achKey, 
					&cbName, 
					NULL, 
					NULL, 
					NULL, 
					&ftLastWriteTime); 
				if (retCode == ERROR_SUCCESS) 
				{
					origsize = strlen(achKey) + 1;
					
					//wcstombs_s(&convertedChars, nstring, origsize, achKey,_TRUNCATE);
					providers[i]=_strdup(achKey);			
				}
			}
		}
		RegCloseKey(hKey);
		
	}
	return cSubKeys;
}