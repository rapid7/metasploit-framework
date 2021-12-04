#include "Win-Ops-Master.h"
#include "NtDefine.h"
#include <sddl.h>
#include <iostream>
#include <threadpoolapiset.h>
#include <random>

DWORD LastError = 0;

OpsMaster::OpsMaster()
{
	LoadLibrary(L"ntdll.dll");
	HMODULE hm = GetModuleHandle(L"ntdll.dll");
	_NtRaiseHardError = (NTSTATUS(WINAPI*)(NTSTATUS ErrorStatus, ULONG NumberOfParameters,
		ULONG UnicodeStringParameterMask, PULONG_PTR * Parameters, ULONG ValidResponseOption, PULONG Response))GetProcAddress(hm, "NtRaiseHardError");
	_RtlAdjustPrivilege = (NTSTATUS(WINAPI*) (ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled))GetProcAddress(hm, "RtlAdjustPrivilege");
	_NtSetInformationFile = (NTSTATUS(WINAPI*) (HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID FileInformation,
		ULONG Length,
		FILE_INFORMATION_CLASS FileInformationClass))GetProcAddress(hm, "NtSetInformationFile");
	_RtlNtStatusToDosError = (ULONG(WINAPI*) (NTSTATUS Status))GetProcAddress(hm, "RtlNtStatusToDosError");
	_RtlInitUnicodeString = (NTSTATUS(WINAPI*)(PUNICODE_STRING, PCWSTR)) GetProcAddress(hm, "RtlInitUnicodeString");
	_NtCreateSymbolicLinkObject = (NTSTATUS(WINAPI*)(
		OUT PHANDLE             pHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		IN PUNICODE_STRING      DestinationName))GetProcAddress(hm, "NtCreateSymbolicLinkObject");
	_NtCreateFile = (NTSTATUS(WINAPI*)(
		PHANDLE            FileHandle,
		ACCESS_MASK        DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PIO_STATUS_BLOCK   IoStatusBlock,
		PLARGE_INTEGER     AllocationSize,
		ULONG              FileAttributes,
		ULONG              ShareAccess,
		ULONG              CreateDisposition,
		ULONG              CreateOptions,
		PVOID              EaBuffer,
		ULONG              EaLength))GetProcAddress(hm, "NtCreateFile");
	_NtSetSecurityObject = (NTSTATUS(WINAPI*)(
		HANDLE               Handle,
		SECURITY_INFORMATION SecurityInformation,
		PSECURITY_DESCRIPTOR SecurityDescriptor
		))GetProcAddress(hm, "NtSetSecurityObject");
	_NtOpenProcess = (NTSTATUS(WINAPI*)(
		PHANDLE            ProcessHandle,
		ACCESS_MASK        DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PCLIENT_ID         ClientId
		))GetProcAddress(hm, "NtOpenProcess");
	_NtTerminateProcess = (NTSTATUS(WINAPI*)(
		IN HANDLE               ProcessHandle OPTIONAL,
		IN NTSTATUS             ExitStatus
		))GetProcAddress(hm, "NtTerminateProcess");
	_NtClose = (NTSTATUS(WINAPI*)(HANDLE Handle))GetProcAddress(hm, "NtClose");
	_NtDeviceIoControlFile = (NTSTATUS(WINAPI*)(
		HANDLE           FileHandle,
		HANDLE           Event,
		PIO_APC_ROUTINE  ApcRoutine,
		PVOID            ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		ULONG            IoControlCode,
		PVOID            InputBuffer,
		ULONG            InputBufferLength,
		PVOID            OutputBuffer,
		ULONG            OutputBufferLength)) GetProcAddress(hm, "NtDeviceIoControlFile");
	_NtCreateDirectoryObjectEx = (NTSTATUS(WINAPI*)(
		PHANDLE, ACCESS_MASK,
		POBJECT_ATTRIBUTES, HANDLE, BOOLEAN
		))GetProcAddress(hm, "NtCreateDirectoryObjectEx");
	_NtOpenDirectoryObject = (NTSTATUS(WINAPI*)(
		PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES
		))GetProcAddress(hm, "NtOpenDirectoryObject");
	_NtWriteFile = (NTSTATUS(WINAPI*)
		(HANDLE           FileHandle,
			HANDLE           Event,
			PIO_APC_ROUTINE  ApcRoutine,
			PVOID            ApcContext,
			PIO_STATUS_BLOCK IoStatusBlock,
			PVOID            Buffer,
			ULONG            Length,
			PLARGE_INTEGER   ByteOffset,
			PULONG           Key)) GetProcAddress(hm, "NtWriteFile");
	_NtWaitForSingleObject = (NTSTATUS(WINAPI*)(
		IN HANDLE               ObjectHandle,
		IN BOOLEAN              Alertable,
		IN PLARGE_INTEGER       TimeOut OPTIONAL)) GetProcAddress(hm, "NtWaitForSingleObject");
	_NtReadFile = (NTSTATUS(WINAPI*)(
		_In_     HANDLE           FileHandle,
		_In_opt_ HANDLE           Event,
		_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
		_In_opt_ PVOID            ApcContext,
		_Out_    PIO_STATUS_BLOCK IoStatusBlock,
		_Out_    PVOID            Buffer,
		_In_     ULONG            Length,
		_In_opt_ PLARGE_INTEGER   ByteOffset,
		_In_opt_ PULONG           Key
		))GetProcAddress(hm, "NtReadFile");
	_NtCompareTokens = (NTSTATUS(WINAPI*)(
		_In_  HANDLE   FirstTokenHandle,
		_In_  HANDLE   SecondTokenHandle,
		_Out_ PBOOLEAN Equal
		)) GetProcAddress(hm, "NtCompareTokens");
	_ZwDeleteFile = (NTSTATUS(WINAPI*)
		(POBJECT_ATTRIBUTES ObjectAttributes))GetProcAddress(hm, "ZwDeleteFile");
	_ZwCreateKey = (NTSTATUS(WINAPI*)
		(PHANDLE            KeyHandle,
			ACCESS_MASK        DesiredAccess,
			POBJECT_ATTRIBUTES ObjectAttributes,
			ULONG              TitleIndex,
			PUNICODE_STRING    Class,
			ULONG              CreateOptions,
			PULONG             Disposition))GetProcAddress(hm, "ZwCreateKey");
	_ZwDeleteKey = (NTSTATUS(WINAPI*)
		(HANDLE KeyHandle))GetProcAddress(hm, "ZwDeleteKey");
	_ZwSetValueKey = (NTSTATUS(WINAPI*)(
		HANDLE          KeyHandle,
		PUNICODE_STRING ValueName,
		ULONG           TitleIndex,
		ULONG           Type,
		PVOID           Data,
		ULONG           DataSize
		))GetProcAddress(hm, "ZwSetValueKey");
	_NtSuspendProcess = (NTSTATUS(WINAPI*)(
		HANDLE ProcessHandle
		))GetProcAddress(hm, "NtSuspendProcess");
	_NtResumeProcess = (NTSTATUS(WINAPI*)(
		HANDLE ProcessHandle
		))GetProcAddress(hm, "NtResumeProcess");
	_ZwMakeTemporaryObject = (NTSTATUS(WINAPI*)(
		HANDLE Handle
		))GetProcAddress(hm, "ZwMakeTemporaryObject");
	_ZwMakePermanentObject = (NTSTATUS(WINAPI*)(
		HANDLE Handle
		))GetProcAddress(hm, "ZwMakePermanentObject");

	return;
}

DWORD OpsMaster::NtStatusToDOS(NTSTATUS status) {
	return _RtlNtStatusToDosError(status);
}

DWORD OpsMaster::GetLastErr() {
	return LastError;
}

void SetLastErr(DWORD err) {
	LastError = err;
}

bool OpsMaster::MoveByHandle(HANDLE hfile, std::wstring target)
{
	size_t destFilenameLength = target.size();
	size_t bufferSize = sizeof(FILE_RENAME_INFO) + (destFilenameLength * sizeof(wchar_t));
	void* buffer = _malloca(bufferSize);
	memset(buffer, 0, bufferSize);
	FILE_RENAME_INFO* rename_info = reinterpret_cast<FILE_RENAME_INFO*>(buffer);
	rename_info->FileNameLength = destFilenameLength;
	rename_info->ReplaceIfExists = TRUE;
	rename_info->RootDirectory = NULL;
	wmemcpy(rename_info->FileName, target.c_str(), destFilenameLength);
	bool ret = SetFileInformationByHandle(hfile, FileRenameInfo, rename_info, bufferSize);
	SetLastErr(GetLastError());
	return ret;
}

bool OpsMaster::MoveByHandle(HANDLE hfile, std::string target) {
	return OpsMaster::MoveByHandle(hfile, std::wstring(target.begin(), target.end()));
}

std::wstring BuildNativePath(std::wstring path) {
	//I am considering any path that start with \ is a native path
	if (path.rfind(L"\\", 0) != std::wstring::npos)
		return path;
	path = L"\\??\\" + path;
	return path;
}

HANDLE OpsMaster::CreateNativeSymlink(std::wstring link, std::wstring target) {
	HANDLE ret;
	UNICODE_STRING ulnk;
	UNICODE_STRING utarget;
	NTSTATUS status;
	if (((status = _RtlInitUnicodeString(&ulnk, link.c_str())) != STATUS_SUCCESS)
		|| ((status = _RtlInitUnicodeString(&utarget, target.c_str())) != STATUS_SUCCESS)) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return NULL;
	}

	OBJECT_ATTRIBUTES objattr;
	InitializeObjectAttributes(&objattr, &ulnk, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	NTSTATUS stat = _NtCreateSymbolicLinkObject(&ret, SYMBOLIC_LINK_ALL_ACCESS,
		&objattr, &utarget);

	if (stat != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(stat));
		return nullptr;
	}
	return ret;
}

HANDLE OpsMaster::CreateNativeSymlink(std::string link, std::string target) {
	return OpsMaster::CreateNativeSymlink(std::wstring(link.begin(), link.end()),
		std::wstring(target.begin(), target.end()));
}
bool OpsMaster::CreateDosDeviceLink(std::string link, std::string target) {
	return OpsMaster::CreateDosDeviceLink(
		std::wstring(link.begin(), link.end()),
		std::wstring(target.begin(), target.end()));
}

bool OpsMaster::CreateDosDeviceLink(std::wstring link, std::wstring target)
{
	if (link[0] == L'\\') {
		link = L"Global\\GLOBALROOT" + link;
	}
	target = BuildNativePath(target);
	DWORD LastErr = GetLastError();
	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, link.c_str(), target.c_str()))
	{
		SetLastErr(GetLastError());
		SetLastError(LastErr);
		return true;
	}
	SetLastErr(GetLastError());
	SetLastError(LastErr);
	return false;
}

bool OpsMaster::RemoveDosDeviceLink(std::string link)
{
	return OpsMaster::RemoveDosDeviceLink(std::wstring(link.begin(), link.end()));
}

bool OpsMaster::RemoveDosDeviceLink(std::wstring link)
{
	if (link[0] == L'\\') {
		link = L"Global\\GLOBALROOT" + link;
	}
	DWORD LastErr = GetLastError();
	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH |
		DDD_REMOVE_DEFINITION,
		link.c_str(), NULL))
	{
		SetLastErr(GetLastError());
		SetLastError(LastErr);
		return true;
	}
	SetLastErr(GetLastError());
	SetLastError(LastErr);
	return false;
}

HANDLE OpsMaster::OpenDirectory(std::wstring directory, DWORD access_mask, DWORD share_mode, DWORD creation_disposition)
{
	directory = BuildNativePath(directory);
	HANDLE h;
	OBJECT_ATTRIBUTES objattr;
	UNICODE_STRING target;
	IO_STATUS_BLOCK io;
	NTSTATUS status;
	_RtlInitUnicodeString(&target, directory.c_str());
	InitializeObjectAttributes(&objattr, &target, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	switch (creation_disposition) {
	case CREATE_NEW:
		status = _NtCreateFile(&h, access_mask, &objattr, &io, NULL, FILE_ATTRIBUTE_NORMAL, share_mode,
			FILE_CREATE, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, NULL);
		break;
	case OPEN_EXISTING:
		status = _NtCreateFile(&h, access_mask, &objattr, &io, NULL, FILE_ATTRIBUTE_NORMAL, share_mode,
			FILE_OPEN, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, NULL);
		break;
	default:
		status = _NtCreateFile(&h, access_mask, &objattr, &io, NULL, FILE_ATTRIBUTE_NORMAL, share_mode,
			FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, NULL);

	}
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return NULL;
	}
	return h;
}

HANDLE OpsMaster::OpenDirectory(std::string directory, DWORD access_mask, DWORD share_mode, DWORD creation_disposition)
{
	return OpsMaster::OpenDirectory(std::wstring(directory.begin(),
		directory.end()), access_mask, share_mode,
		creation_disposition);
}

HANDLE OpsMaster::OpenFileNative(std::wstring file, DWORD access_mask, DWORD share_mode, DWORD creation_dispostion)
{
	file = BuildNativePath(file);
	access_mask |= SYNCHRONIZE;
	OBJECT_ATTRIBUTES objattr;
	UNICODE_STRING target;
	IO_STATUS_BLOCK io;
	_RtlInitUnicodeString(&target, file.c_str());
	InitializeObjectAttributes(&objattr, &target, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	NTSTATUS status;
	HANDLE ret = 0;
	switch (creation_dispostion) {
	case OPEN_EXISTING:
		status = _NtCreateFile(&ret, access_mask, &objattr, &io, NULL, NULL, share_mode, FILE_OPEN,
			FILE_NON_DIRECTORY_FILE, NULL, NULL);
		break;
	case OPEN_ALWAYS:
		status = _NtCreateFile(&ret, access_mask, &objattr, &io, NULL, NULL, share_mode, FILE_OPEN_IF,
			FILE_NON_DIRECTORY_FILE, NULL, NULL);
		break;
	case CREATE_ALWAYS:
		status = _NtCreateFile(&ret, access_mask, &objattr, &io, NULL, NULL, share_mode, FILE_OVERWRITE_IF,
			FILE_NON_DIRECTORY_FILE, NULL, NULL);
		break;
	case CREATE_NEW:
		status = _NtCreateFile(&ret, access_mask, &objattr, &io, NULL, NULL, share_mode, FILE_CREATE,
			FILE_NON_DIRECTORY_FILE, NULL, NULL);
		break;
	case TRUNCATE_EXISTING:
		status = _NtCreateFile(&ret, access_mask, &objattr, &io, NULL, NULL, share_mode, FILE_OVERWRITE,
			FILE_NON_DIRECTORY_FILE, NULL, NULL);
		break;
	}
	if (status != STATUS_SUCCESS)
		SetLastErr(_RtlNtStatusToDosError(status));
	return ret;
}

HANDLE OpsMaster::OpenFileNative(std::string file, DWORD access_mask, DWORD share_mode, DWORD creation_dispostion)
{
	return OpsMaster::OpenFileNative(std::wstring(file.begin(), file.end()),
		access_mask, share_mode, creation_dispostion);
}

bool OpsMaster::WriteFileNative(HANDLE hfile, PVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten)
{
	IO_STATUS_BLOCK io;
	LARGE_INTEGER li;
	li.LowPart = 0;
	li.HighPart = 0;
	NTSTATUS status = _NtWriteFile(hfile, NULL,
		NULL, NULL, &io, lpBuffer, nNumberOfBytesToWrite, &li, NULL);
	if (status == STATUS_PENDING)
		status = _NtWaitForSingleObject(hfile, FALSE, NULL);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	if (lpNumberOfBytesWritten != nullptr)
		*lpNumberOfBytesWritten = io.Information;
	return true;
}

bool OpsMaster::ReadFileNative(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead)
{
	if (nNumberOfBytesToRead == 0) {
		LARGE_INTEGER sz;
		GetFileSizeEx(hFile, &sz);
		nNumberOfBytesToRead = sz.QuadPart;
	}
	LARGE_INTEGER offset;
	offset.LowPart = 0;
	offset.HighPart = 0;
	IO_STATUS_BLOCK io;
	NTSTATUS status = _NtReadFile(hFile, NULL, NULL, NULL,
		&io, lpBuffer, nNumberOfBytesToRead, &offset, NULL);
	if (status == STATUS_PENDING)
		status = _NtWaitForSingleObject(hFile, FALSE, NULL);

	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	if (lpNumberOfBytesRead != nullptr)
		*lpNumberOfBytesRead = io.Information;
	return true;
}

HANDLE OpsMaster::OpenProcessNative(DWORD PID, DWORD access_mask)
{
	HANDLE hret = nullptr;
	OBJECT_ATTRIBUTES objattr;
	CLIENT_ID id = { (HANDLE)PID,0 };
	InitializeObjectAttributes(&objattr, 0, 0, 0, 0);
	NTSTATUS status = _NtOpenProcess(&hret, access_mask, &objattr, &id);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
	}
	return hret;
}

bool OpsMaster::SuspendProcess(HANDLE hprocess)
{
	NTSTATUS status = _NtSuspendProcess(hprocess);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

bool OpsMaster::ResumeProcess(HANDLE hprocess)
{
	NTSTATUS status = _NtResumeProcess(hprocess);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

bool OpsMaster::TerminateProcessNative(DWORD process_id)
{
	CLIENT_ID id = { (HANDLE)process_id, 0 };
	OBJECT_ATTRIBUTES objattr;
	InitializeObjectAttributes(&objattr, 0, 0, 0, 0);
	HANDLE proc;
	NTSTATUS status = _NtOpenProcess(&proc, PROCESS_TERMINATE, &objattr, &id);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	status = _NtTerminateProcess(proc, STATUS_SUCCESS);
	_NtClose(proc);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}
bool OpsMaster::TerminateProcessNative(HANDLE hprocess)
{
	NTSTATUS status = _NtTerminateProcess(hprocess, STATUS_SUCCESS);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

HANDLE OpsMaster::SetTokenDosDevice(std::wstring device_path, HANDLE htoken)
{
	if (htoken != NULL) {
		ImpersonateLoggedOnUser(htoken);
	}
	HANDLE hret = OpsMaster::CreateNativeSymlink(std::wstring(L"\\??\\c:"), std::wstring(device_path));
	if (htoken != NULL) {
		RevertToSelf();
	}
	return hret;
}

HANDLE OpsMaster::SetTokenDosDevice(std::string device_path, HANDLE htoken)
{
	return OpsMaster::SetTokenDosDevice(std::wstring(device_path.begin(), device_path.end()),
		htoken);
}

void OpsMaster::bsod() {
	BOOLEAN b;
	ULONG r;
	_RtlAdjustPrivilege(19, true, false, &b);
	_NtRaiseHardError(0xDeadDead, 0, 0, 0, 6, &r);
	return;
}

HANDLE OpsMaster::OpenNamedPipe(std::wstring pipe_name, DWORD desired_access, DWORD impersonation_level)
{

	UNICODE_STRING pipe;
	OBJECT_ATTRIBUTES objattr;
	HANDLE ret;
	IO_STATUS_BLOCK io;
	_RtlInitUnicodeString(&pipe, pipe_name.c_str());
	InitializeObjectAttributes(&objattr, &pipe, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	DWORD dwattr = FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | impersonation_level;
	NTSTATUS status = _NtCreateFile(&ret, desired_access, &objattr, &io, NULL, dwattr, ALL_SHARING,
		FILE_OPEN, NULL, NULL, NULL);

	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return NULL;
	}
	return ret;
}

HANDLE OpsMaster::OpenNamedPipe(std::string pipe_name, DWORD desired_access, DWORD impersonation_level)
{
	return OpsMaster::OpenNamedPipe(std::wstring(pipe_name.begin(), pipe_name.end()),
		desired_access, impersonation_level);
}

bool OpsMaster::CreateNativeHardLink(HANDLE hfile, std::wstring target)
{
	target = BuildNativePath(target);
	IO_STATUS_BLOCK io;

	FILE_LINK_INFORMATION* link_inf = (FILE_LINK_INFORMATION*)_malloca(sizeof(FILE_LINK_INFORMATION) + (target.size() * sizeof(WCHAR)));

	memset(link_inf, 0, sizeof(FILE_LINK_INFORMATION) + (target.size() * sizeof(WCHAR)));

	link_inf->FileNameLength = target.size() * sizeof(WCHAR);
	link_inf->ReplaceIfExists = TRUE;
	link_inf->RootDirectory = NULL;
	memcpy(&link_inf->FileName[0], target.c_str(), target.size() * sizeof(WCHAR));

	NTSTATUS status = _NtSetInformationFile(hfile, &io, link_inf, sizeof(FILE_LINK_INFORMATION) + (target.size() * sizeof(WCHAR)), FileLinkInformation);

	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

bool OpsMaster::CreateNativeHardLink(HANDLE hfile, std::string target)
{
	return OpsMaster::CreateNativeHardLink(hfile, std::wstring(target.begin(), target.end()));
}

bool OpsMaster::CreateNativeHardLink(std::wstring link, std::wstring target)
{

	// Before windows hardlink mitigation, only GENERIC_READ is required to create the hardlink
	// but since the mitigation, WRITE_ATTRIBUTES is now required to create a hardlink
	// the best solution for me here is to open the file with MAXIMUM_ALLOWED
	HANDLE hf = OpsMaster::OpenFileNative(link);
	bool ret = OpsMaster::CreateNativeHardLink(hf, target);
	_NtClose(hf);
	return ret;
}

bool OpsMaster::CreateNativeHardLink(std::string link, std::string target)
{
	// Before windows hardlink mitigation, only GENERIC_READ is required to create the hardlink
	// but since the mitigation, WRITE_ATTRIBUTES is now required to create a hardlink
	// the best solution for me here is to open the file with MAXIMUM_ALLOWED
	HANDLE hf = OpsMaster::OpenFileNative(link);
	bool ret = OpsMaster::CreateNativeHardLink(hf, target);
	_NtClose(hf);
	return ret;
}

bool OpsMaster::CreateMountPoint(HANDLE hdir, std::wstring target, std::wstring printname)
{
	target = BuildNativePath(target);
	size_t targetsz = target.size() * 2;
	size_t printnamesz = printname.size() * 2;
	size_t pathbuffersz = targetsz + printnamesz + 12;
	size_t totalsz = pathbuffersz + REPARSE_DATA_BUFFER_HEADER_LENGTH;
	REPARSE_DATA_BUFFER* rdb = (REPARSE_DATA_BUFFER*)_malloca(totalsz);
	memset(rdb, 0, totalsz);
	rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	rdb->ReparseDataLength = static_cast<USHORT>(pathbuffersz);
	rdb->Reserved = NULL;
	rdb->MountPointReparseBuffer.SubstituteNameOffset = NULL;
	rdb->MountPointReparseBuffer.SubstituteNameLength = static_cast<USHORT>(targetsz);
	memcpy(rdb->MountPointReparseBuffer.PathBuffer, target.c_str(), targetsz + 2);
	rdb->MountPointReparseBuffer.PrintNameOffset = static_cast<USHORT>(targetsz + 2);
	rdb->MountPointReparseBuffer.PrintNameLength = static_cast<USHORT>(printnamesz);
	memcpy(rdb->MountPointReparseBuffer.PathBuffer + target.size() + 1, printname.c_str(), printnamesz + 2);
	DWORD cb = 0;
	OVERLAPPED ov = { 0 };
	HANDLE hevent = CreateEvent(NULL, FALSE, FALSE, NULL);
	ov.hEvent = hevent;
	BOOL ret = DeviceIoControl(hdir, FSCTL_SET_REPARSE_POINT, rdb, totalsz, NULL, NULL, NULL, &ov);
	WaitForSingleObject(hevent, INFINITE);
	CloseHandle(hevent);
	return ret;
}

bool OpsMaster::CreateMountPoint(HANDLE hdir, std::string target, std::string printname)
{
	return OpsMaster::CreateMountPoint(hdir, std::wstring(target.begin(), target.end()),
		std::wstring(printname.begin(), printname.end()));
}

bool OpsMaster::CreateMountPoint(std::wstring dir, std::wstring target, std::wstring printname)
{
	HANDLE hdir = OpenDirectory(dir, FILE_WRITE_DATA, ALL_SHARING, OPEN_ALWAYS);
	bool ret = CreateMountPoint(hdir, target, printname);
	_NtClose(hdir);
	return ret;
}

bool OpsMaster::CreateMountPoint(std::string dir, std::string target, std::string printname)
{
	return OpsMaster::CreateMountPoint(std::wstring(dir.begin(), dir.end()),
		std::wstring(target.begin(), target.end()), std::wstring(printname.begin(), printname.end()));
}

bool OpsMaster::DeleteMountPoint(HANDLE hdir)
{
	REPARSE_GUID_DATA_BUFFER rp_buffer = { 0 };
	rp_buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	DWORD cb = 0;
	return DeviceIoControl(hdir, FSCTL_DELETE_REPARSE_POINT, &rp_buffer, REPARSE_GUID_DATA_BUFFER_HEADER_SIZE,
		nullptr, NULL, &cb, NULL) == TRUE;
}

bool OpsMaster::DeleteMountPoint(std::wstring dir)
{
	HANDLE hdir = OpenDirectory(dir, FILE_WRITE_DATA, ALL_SHARING, OPEN_EXISTING);
	bool rt = OpsMaster::DeleteMountPoint(hdir);
	_NtClose(hdir);
	return rt;
}

bool OpsMaster::DeleteMountPoint(std::string dir)
{
	HANDLE hdir = OpenDirectory(dir, FILE_WRITE_DATA, ALL_SHARING, OPEN_EXISTING);
	bool rt = OpsMaster::DeleteMountPoint(hdir);
	_NtClose(hdir);
	return rt;
}

std::wstring OpsMaster::GetMountPointData(HANDLE hdir, std::wstring)
{
	REPARSE_DATA_BUFFER* rdb = (REPARSE_DATA_BUFFER*)_malloca(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);

	DWORD rd = 0;

	if (!DeviceIoControl(hdir, FSCTL_GET_REPARSE_POINT, NULL,
		NULL, rdb, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &rd, nullptr))
		return L"";
	WCHAR* bs = &rdb->MountPointReparseBuffer.PathBuffer[rdb->MountPointReparseBuffer.SubstituteNameOffset / 2];

	return std::wstring(bs, bs + (rdb->MountPointReparseBuffer.SubstituteNameLength / 2));
}

std::string OpsMaster::GetMountPointData(HANDLE hdir, std::string)
{
	std::wstring rt = OpsMaster::GetMountPointData(hdir, L"");
	return std::string(rt.begin(), rt.end());
}

std::wstring OpsMaster::GetMountPointData(std::wstring dir)
{
	HANDLE hdir = OpsMaster::OpenDirectory(dir, GENERIC_READ, ALL_SHARING, OPEN_EXISTING);
	std::wstring ret = OpsMaster::GetMountPointData(hdir, L"");
	_NtClose(hdir);
	return ret;
}

std::string OpsMaster::GetMountPointData(std::string dir)
{
	HANDLE hdir = OpsMaster::OpenDirectory(dir, GENERIC_READ, ALL_SHARING, OPEN_EXISTING);
	std::string ret = OpsMaster::GetMountPointData(hdir, "");
	_NtClose(hdir);
	return ret;
}

HANDLE OpsMaster::CreateObjDir(std::wstring dir)
{
	HANDLE rt = NULL;
	OBJECT_ATTRIBUTES objattr;
	UNICODE_STRING target;
	_RtlInitUnicodeString(&target, dir.c_str());
	InitializeObjectAttributes(&objattr, &target, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	NTSTATUS status = _NtCreateDirectoryObjectEx(&rt, MAXIMUM_ALLOWED, &objattr, nullptr, FALSE);


	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return NULL;
	}
	return rt;
}

HANDLE OpsMaster::CreateObjDir(std::string dir)
{
	return OpsMaster::CreateObjDir(std::wstring(dir.begin(), dir.end()));
}

HANDLE OpsMaster::OpenObjDir(std::wstring dir)
{
	OBJECT_ATTRIBUTES objattr;
	HANDLE ret;
	UNICODE_STRING udir;
	_RtlInitUnicodeString(&udir, dir.c_str());
	InitializeObjectAttributes(&objattr, &udir, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS status = _NtOpenDirectoryObject(&ret, MAXIMUM_ALLOWED, &objattr);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return NULL;
	}
	return ret;
}

HANDLE OpsMaster::OpenObjDir(std::string dir)
{
	return OpsMaster::OpenObjDir(std::wstring(dir.begin(), dir.end()));
}

bool OpsMaster::MakePermanentObj(HANDLE hobj)
{
	NTSTATUS status = _ZwMakePermanentObject(hobj);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

bool OpsMaster::CreateAndWaitLock(std::wstring file, _UserCallback cb, bool IsDirectory)
{
	HANDLE h;
	if (IsDirectory)
		h = OpenDirectory(file);

	else
		h = OpenFileNative(file);
	if (h == INVALID_HANDLE_VALUE)
		return false;
	lock_ptr lk = FileOpLock::CreateLock(h, cb);
	if (lk != nullptr) { lk->WaitForLock(INFINITE); }
	else {
		_NtClose(h);
		delete lk;
		return false;
	}
	_NtClose(h);
	delete lk;
	return true;
}

bool OpsMaster::CreateAndWaitLock(std::string file, _UserCallback cb, bool IsDirectory)
{
	return OpsMaster::CreateAndWaitLock(std::wstring(file.begin(), file.end()), cb, IsDirectory);
}

bool OpsMaster::CreateAndWaitLock(HANDLE h, _UserCallback cb)
{
	FileOpLock* lk = FileOpLock::CreateLock(h, cb);
	if (lk != nullptr) {
		lk->WaitForLock(INFINITE);
		return false;
	}
	return true;
}

lock_ptr OpsMaster::CreateLock(HANDLE h, _UserCallback cb)
{
	lock_ptr lk = FileOpLock::CreateLock(h, cb);
	return lk;
}

lock_ptr OpsMaster::CreateLock(std::wstring file, _UserCallback cb, bool IsDirectory)
{
	HANDLE g;
	if (IsDirectory)
		g = OpsMaster::OpenDirectory(file);
	else
		g = OpsMaster::OpenFileNative(file);
	return OpsMaster::CreateLock(g, cb);
}

lock_ptr OpsMaster::CreateLock(std::string file, _UserCallback cb, bool IsDirectory)
{
	return OpsMaster::CreateLock(std::wstring(file.begin(), file.end()), cb, IsDirectory);
}

bool OpsMaster::MoveFileToTempDir(HANDLE h, DWORD temp_location, std::wstring loc)
{

	std::wstring randomstr = this->GenerateRandomStr();
	std::wstring path_to_move;
	WCHAR temp_path[MAX_PATH];
	switch (temp_location) {
	case USE_USER_TEMP_DIR:
		ExpandEnvironmentStrings(L"%TEMP%", temp_path, MAX_PATH);
		path_to_move = temp_path + std::wstring(L"\\") + randomstr;
		return MoveByHandle(h, path_to_move);
		break;
	case USE_SYSTEM_TEMP_DIR:
		GetWindowsDirectory(temp_path, MAX_PATH);
		path_to_move = temp_path + std::wstring(L"\\Temp\\") + randomstr;
		return MoveByHandle(h, path_to_move);
		break;
	case USE_CUSTOM_TEMP_DIR:
		path_to_move = loc + std::wstring(L"\\") + randomstr;
		return MoveByHandle(h, path_to_move);
		break;
	}
	return false;
}

bool OpsMaster::MoveFileToTempDir(std::wstring file, bool IsDirectory, DWORD temp_location, std::wstring loc)
{
	HANDLE g;
	if (IsDirectory)
		g = OpsMaster::OpenDirectory(file, DELETE, ALL_SHARING, OPEN_EXISTING);
	else
		g = OpsMaster::OpenFileNative(file, DELETE, ALL_SHARING, OPEN_EXISTING);
	return OpsMaster::MoveFileToTempDir(g, temp_location, L"");
}

bool OpsMaster::MoveFileToTempDir(std::string file, bool IsDirectory, DWORD temp_location, std::string loc)
{
	return OpsMaster::MoveFileToTempDir(std::wstring(file.begin(), file.end()), IsDirectory, temp_location,
		std::wstring(loc.begin(), loc.end()));
}

bool OpsMaster::DeleteChild(HANDLE root, std::wstring child)
{
	OBJECT_ATTRIBUTES objattr;
	UNICODE_STRING _child;
	_RtlInitUnicodeString(&_child, child.c_str());
	InitializeObjectAttributes
	(
		&objattr,//object attributes pointer
		&_child,//object name in this case the file to be deleted
		OBJ_CASE_INSENSITIVE,//object attributes
		root,//root directory HANDLE
		NULL//security descriptor must be null
	);
	NTSTATUS status = _ZwDeleteFile(&objattr);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

bool OpsMaster::RRemoveDirectory(std::wstring dir)
{

	DWORD fst_attr = GetFileAttributes(dir.c_str());
	if (fst_attr & FILE_ATTRIBUTE_NORMAL)
		return DeleteFile(dir.c_str());
	if (fst_attr & FILE_ATTRIBUTE_REPARSE_POINT)
		return RemoveDirectoryW(dir.c_str());
	std::wstring search_path = std::wstring(dir) + L"\\*.*";
	std::wstring s_p = std::wstring(dir) + std::wstring(L"\\");
	WIN32_FIND_DATA fd;
	HANDLE hFind = FindFirstFile(search_path.c_str(), &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
			{
				continue;
			}
			if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				DeleteFile(std::wstring(s_p + fd.cFileName).c_str());
				continue;
			}
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
				RemoveDirectory(std::wstring(s_p + fd.cFileName).c_str());
				continue;
			}
			if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0)
			{
				OpsMaster::RRemoveDirectory(s_p + fd.cFileName);
			}
		} while (FindNextFile(hFind, &fd));
		FindClose(hFind);
	}
	if (RemoveDirectoryW(dir.c_str()) != 0) {
		return false;
	}
	return true;
}


bool OpsMaster::RRemoveDirectory(std::string dir)
{
	return OpsMaster::RRemoveDirectory(std::wstring(dir.begin(), dir.end()));
}

bool OpsMaster::DeleteByHandle(HANDLE hfile)
{
	FILE_DISPOSITION_INFORMATION_EX dispositioninfo = { 0 };
	dispositioninfo.Flags = FILE_DISPOSITION_DELETE | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE;
	IO_STATUS_BLOCK io;
	NTSTATUS status = _NtSetInformationFile(hfile, &io, &dispositioninfo, sizeof(FILE_DISPOSITION_INFORMATION_EX), FileDispositionInformationEx);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}


std::wstring OpsMaster::GenerateRandomStr()
{
	GUID gg;
	HRESULT hs = CoCreateGuid(&gg);
	WCHAR mx[MAX_PATH];
	int x = StringFromGUID2(gg, mx, MAX_PATH);
	return mx;
}




OpsMaster::FileOpLock::FileOpLock(UserCallback cb) :
	g_inputBuffer({ 0 }), g_outputBuffer({ 0 }), g_o({ 0 }), g_hFile(INVALID_HANDLE_VALUE), g_hLockCompleted(nullptr), g_wait(nullptr), _cb(cb)
{
	g_inputBuffer.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
	g_inputBuffer.StructureLength = sizeof(g_inputBuffer);
	g_inputBuffer.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
	g_inputBuffer.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;
	g_outputBuffer.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
	g_outputBuffer.StructureLength = sizeof(g_outputBuffer);
}


OpsMaster::FileOpLock::~FileOpLock()
{
	if (g_wait)
	{
		SetThreadpoolWait(g_wait, nullptr, nullptr);
		CloseThreadpoolWait(g_wait);
		g_wait = nullptr;
	}

	if (g_o.hEvent)
	{
		CloseHandle(g_o.hEvent);
		g_o.hEvent = nullptr;
	}

	if (g_hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(g_hFile);
		g_hFile = INVALID_HANDLE_VALUE;
	}
}

bool OpsMaster::FileOpLock::BeginLock(HANDLE h)
{
	g_hLockCompleted = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	g_o.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

	g_hFile = h;
	g_wait = CreateThreadpoolWait(WaitCallback, this, nullptr);
	if (g_wait == nullptr)
	{
		return false;
	}

	SetThreadpoolWait(g_wait, g_o.hEvent, nullptr);

	DWORD bytesReturned;
	DeviceIoControl(g_hFile, FSCTL_REQUEST_OPLOCK,
		&g_inputBuffer, sizeof(g_inputBuffer),
		&g_outputBuffer, sizeof(g_outputBuffer),
		nullptr, &g_o);

	SetLastErr(GetLastError());
	if (GetLastError() != ERROR_IO_PENDING) {
		return false;
	}
	return true;
}

OpsMaster::FileOpLock* OpsMaster::FileOpLock::CreateLock(HANDLE h, OpsMaster::FileOpLock::UserCallback cb)
{
	OpsMaster::FileOpLock* ret = new OpsMaster::FileOpLock(cb);
	if (ret->BeginLock(h))
	{
		return ret;
	}
	else
	{
		delete ret;
		return nullptr;
	}
}

void OpsMaster::FileOpLock::WaitForLock(UINT Timeout)
{
	WaitForSingleObject(g_hLockCompleted, Timeout);
}

void OpsMaster::FileOpLock::WaitCallback(PTP_CALLBACK_INSTANCE Instance,
	PVOID Parameter, PTP_WAIT Wait,
	TP_WAIT_RESULT WaitResult)
{
	UNREFERENCED_PARAMETER(Instance);
	UNREFERENCED_PARAMETER(Wait);
	UNREFERENCED_PARAMETER(WaitResult);

	OpsMaster::FileOpLock* lock = reinterpret_cast<FileOpLock*>(Parameter);

	lock->DoWaitCallback();
}

void OpsMaster::FileOpLock::DoWaitCallback()
{
	DWORD dwBytes;
	if (!GetOverlappedResult(g_hFile, &g_o, &dwBytes, TRUE)) {
	}

	if (_cb)
	{
		_cb();
	}

	CloseHandle(g_hFile);
	g_hFile = INVALID_HANDLE_VALUE;
	SetEvent(g_hLockCompleted);
}

std::wstring OpsMaster::GetUserSid(HANDLE htoken) {
	DWORD dwSize;

	GetTokenInformation(htoken, TokenUser, nullptr, 0, &dwSize);

	std::vector<BYTE> userbuffer(dwSize);

	GetTokenInformation(htoken, TokenUser, &userbuffer[0], dwSize, &dwSize);

	PTOKEN_USER user = reinterpret_cast<PTOKEN_USER>(&userbuffer[0]);

	LPWSTR lpUser;
	std::wstring ret = L"";

	if (ConvertSidToStringSid(user->User.Sid, &lpUser))
	{
		ret = lpUser;
		LocalFree(lpUser);
	}

	return ret;
}

HANDLE OpsMaster::GetAnonymousToken()
{
	HANDLE htoken = NULL;
	HANDLE hret = NULL;
	ImpersonateAnonymousToken(GetCurrentThread());
	OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &htoken);
	//just in case
	DuplicateHandle(GetCurrentProcess(), htoken, GetCurrentProcess(),
		&hret, TOKEN_ALL_ACCESS, FALSE, DUPLICATE_CLOSE_SOURCE);
	return hret;
}

bool OpsMaster::MakeTemporaryObj(HANDLE hobj)
{
	NTSTATUS status = _ZwMakeTemporaryObject(hobj);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

std::wstring OpsMaster::GetCurrentExeDir()
{
	WCHAR mx[MAX_PATH];
	GetModuleFileName(GetModuleHandle(NULL), mx, MAX_PATH);
	std::wstring ret = mx;
	for (int i = ret.size(); i > 0; i--) {
		if (ret[i] != L'\\') {
			continue;
		}
		ret.erase(i, ret.size());
		break;
	}
	return ret;
}

std::wstring OpsMaster::GetCurrentExeDirWithFileAppended(std::wstring file)
{

	return OpsMaster::GetCurrentExeDir() + L"\\" + file;
}

std::wstring OpsMaster::RegPathToNative(LPCWSTR lpPath)
{
	std::wstring regpath = L"\\REGISTRY\\";

	// Already native rooted
	if (lpPath[0] == '\\')
	{
		return lpPath;
	}

	if (_wcsnicmp(lpPath, L"HKLM\\", 5) == 0)
	{
		return regpath + L"MACHINE\\" + &lpPath[5];
	}
	else if (_wcsnicmp(lpPath, L"HKEY_LOCAL_MACHINE\\", 19) == 0) {
		return regpath + L"MACHINE\\" + &lpPath[19];
	}
	else if (_wcsnicmp(lpPath, L"HKU\\", 4) == 0)
	{
		return regpath + L"USER\\" + &lpPath[4];
	}
	else if (_wcsnicmp(lpPath, L"HKEY_USERS\\", 11) == 0)
	{
		return regpath + L"USER\\" + &lpPath[11];
	}
	else if (_wcsnicmp(lpPath, L"HKCU\\", 5) == 0)
	{
		std::wstring ret = regpath + L"USER\\" + GetUserSid().c_str() + L"\\" + &lpPath[5];
		return ret;
	}
	else if (_wcsnicmp(lpPath, L"HKEY_CURRENT_USER\\", 18) == 0)
	{
		std::wstring ret = regpath + L"USER\\" + GetUserSid().c_str() + L"\\" + &lpPath[18];
		return ret;
	}
	else
	{
		//error
		return L"";
	}
}

HANDLE OpsMaster::RegCreateKeyNative(std::wstring target, DWORD desired_access, bool OpenLink, bool CreateLink)
{
	HANDLE hret = NULL;
	UNICODE_STRING _target;
	target = RegPathToNative(target.c_str());
	_RtlInitUnicodeString(&_target, target.c_str());
	DWORD _objflag = OBJ_CASE_INSENSITIVE | (OpenLink ? OBJ_OPENLINK : NULL);
	OBJECT_ATTRIBUTES objattr;
	InitializeObjectAttributes(&objattr, &_target, _objflag, NULL, NULL);
	if (!(desired_access & KEY_WOW64_64KEY)) {
		desired_access |= KEY_WOW64_64KEY;
	}
	NTSTATUS status = _ZwCreateKey(&hret, desired_access,
		&objattr, NULL, NULL,
		(CreateLink ? INTERNAL_REG_OPTION_CREATE_LINK : NULL) | REG_OPTION_NON_VOLATILE, NULL);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
	}
	return hret;
}

HANDLE OpsMaster::RegCreateKeyNative(std::string target, DWORD desired_access, bool OpenLink, bool CreateLink) {
	return OpsMaster::RegCreateKeyNative(
		std::wstring(target.begin(), target.end()),
		desired_access, OpenLink, CreateLink
	);
}

bool OpsMaster::RegDeleteKeyNative(HANDLE hkey) {

	NTSTATUS status = _ZwDeleteKey(hkey);
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;
}

bool OpsMaster::RegDeleteKeyNative(std::wstring target) {
	HANDLE hk = OpsMaster::RegCreateKeyNative(target, DELETE, true);
	bool ret = OpsMaster::RegDeleteKeyNative(hk);
	_NtClose(hk);
	return ret;
}

bool OpsMaster::RegDeleteKeyNative(std::string target) {
	return OpsMaster::RegDeleteKeyNative(std::wstring(target.begin(), target.end()));
}

bool OpsMaster::RegCreateNativeLink(HANDLE hkey, std::wstring target) {

	OBJECT_ATTRIBUTES objattr;
	UNICODE_STRING value;
	target = RegPathToNative(target.c_str());
	_RtlInitUnicodeString(&value, L"SymbolicLinkValue");

	NTSTATUS status = _ZwSetValueKey(hkey, &value, NULL, REG_LINK,
		(PVOID)target.c_str(), target.length() * sizeof(WCHAR));
	if (status != STATUS_SUCCESS) {
		SetLastErr(_RtlNtStatusToDosError(status));
		return false;
	}
	return true;

}
bool OpsMaster::RegCreateNativeLink(HANDLE hkey, std::string target) {
	return OpsMaster::RegCreateNativeLink(hkey, std::wstring(target.begin(), target.end()));
}
bool OpsMaster::RegCreateNativeLink(std::wstring link, std::wstring target) {
	HANDLE hk = OpsMaster::RegCreateKeyNative(link, KEY_CREATE_LINK | KEY_WRITE, true, true);
	if (!hk) {
		return false;
	}
	bool ret = OpsMaster::RegCreateNativeLink(hk, target);
	_NtClose(hk);
	return ret;
}
bool OpsMaster::RegCreateNativeLink(std::string link, std::string target) {
	std::wstring lnk = std::wstring(link.begin(), link.end());
	std::wstring _target = std::wstring(target.begin(), target.end());
	return OpsMaster::RegCreateNativeLink(lnk,
		_target);
}
