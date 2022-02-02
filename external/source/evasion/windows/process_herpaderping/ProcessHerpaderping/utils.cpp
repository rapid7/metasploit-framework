#include "pch.hpp"
#include "utils.hpp"

_Use_decl_annotations_
std::wstring Utils::FormatError(uint32_t Error)
{
    LPWSTR buffer;
    std::wstring message;
    auto length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                     FORMAT_MESSAGE_FROM_SYSTEM |
                                     FORMAT_MESSAGE_IGNORE_INSERTS,
                                 nullptr,
                                 Error,
                                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                 RCAST(LPWSTR)(&buffer),
                                 0,
                                 nullptr);
    if ((buffer != nullptr) && (length > 0))
    {
        message = std::wstring(buffer, length);
    }
    else
    {
        length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                    FORMAT_MESSAGE_FROM_SYSTEM |
                                    FORMAT_MESSAGE_FROM_HMODULE |
                                    FORMAT_MESSAGE_IGNORE_INSERTS,
                                GetModuleHandleA("ntdll.dll"),
                                Error,
                                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                RCAST(LPWSTR)(&buffer),
                                0,
                                nullptr);
        if ((buffer != nullptr) && (length > 0))
        {
            //
            // NT status codes are formatted with inserts, only use the 
            // initial description if there is one, otherwise just use the 
            // string as is.
            //
            message = std::wstring(buffer, length);
            if (message[0] == L'{')
            {
                auto pos = message.find(L'}', 1);
                if (pos != std::wstring::npos)
                {
                    message = std::wstring(message.begin() + 1,
                                           message.begin() + pos);
                }
            }
        }
    }

    if (message.empty())
    {
        message = L"Unknown Error";
    }

    std::wstringstream ss;
    ss << L"0x"
       << std::hex << std::setfill(L'0') << std::setw(8) << Error 
       << L" - "
       << std::move(message);

    auto res = ss.str();
    EraseAll(res, { L'\r', L'\n', L'\t' });

    LocalFree(buffer);

    return res;
}

_Use_decl_annotations_
HRESULT Utils::FillBufferWithPattern(
    std::vector<uint8_t>& Buffer,
    std::span<const uint8_t> Pattern)
{
    if (Buffer.empty())
    {
        REPORT_AND_RETURN_WIN32("FillBufferWithPattern: Buffer is empty", ERROR_INVALID_PARAMETER);
    }

    auto bytesRemaining = Buffer.size();
    while (bytesRemaining > 0)
    {
        auto len = (Pattern.size() > bytesRemaining ? 
                    bytesRemaining 
                    : 
                    Pattern.size());

        std::memcpy(&Buffer[Buffer.size() - bytesRemaining],
                    Pattern.data(),
                    len);

        bytesRemaining -= len;
    }

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::GetFileSize(
    handle_t FileHandle,
    uint64_t& FileSize)
{
    FileSize = 0;

    LARGE_INTEGER fileSize;
    if (GetFileSizeEx(FileHandle, &fileSize) == 0)
    {
        REPORT_AND_RETURN_WIN32("GetFileSize: Error getting file size", GetLastError());
    }

    if (fileSize.QuadPart < 0)
    {
        REPORT_AND_RETURN_WIN32("GetFileSize: Invalid file size", ERROR_FILE_INVALID);
    }

    FileSize = fileSize.QuadPart;
    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::SetFilePointer(
    handle_t FileHandle,
    int64_t DistanceToMove,
    uint32_t MoveMethod)
{
    LARGE_INTEGER distance;
    distance.QuadPart = DistanceToMove;

    if (SetFilePointerEx(FileHandle, distance, nullptr, MoveMethod) == 0)
    {
        REPORT_AND_RETURN_WIN32("SetFilePointer: Error returned by SetFilePointerEx()", GetLastError());
    }

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::CopyFileByHandle(
    handle_t SourceHandle, 
    handle_t TargetHandle)
{
    //
    // Get the file sizes.
    //
    uint64_t sourceSize;
    if (FAILED(GetFileSize(SourceHandle, sourceSize)))
    {
        REPORT_AND_RETURN_WIN32("CopyFileByHandle: Error getting source file  size", GetLastError());
    }

    //
    // Set the file pointers to the beginning of the files.
    //
    HRESULT hr = SetFilePointer(SourceHandle, 0, FILE_BEGIN);
    if (FAILED(hr))
    {
        REPORT_AND_RETURN_HR("CopyFileByHandle: Error setting source file pointer", hr);
    }
    hr = SetFilePointer(TargetHandle, 0, FILE_BEGIN);
    if (FAILED(hr))
    {
        REPORT_AND_RETURN_HR("CopyFileByHandle: Error setting target file pointer", hr);
    }

    uint64_t bytesRemaining = sourceSize; 
    std::vector<uint8_t> buffer;
    if (bytesRemaining > MaxFileBuffer)
    {
        buffer.assign(MaxFileBuffer, 0);
    }
    else
    {
        buffer.assign(SCAST(size_t)(bytesRemaining), 0);
    }

    while (bytesRemaining > 0)
    {
        if (bytesRemaining < buffer.size())
        {
            buffer.assign(SCAST(size_t)(bytesRemaining), 0);
        }

        DWORD bytesRead = 0;
        if (ReadFile(SourceHandle, buffer.data(), SCAST(DWORD)(buffer.size()), &bytesRead, nullptr) == 0)
        {
            REPORT_AND_RETURN_WIN32("CopyFileByHandle: Error reading source file", GetLastError());
        }

        bytesRemaining -= bytesRead;

        DWORD bytesWitten = 0;
        if (WriteFile(TargetHandle, buffer.data(), SCAST(DWORD)(buffer.size()), &bytesWitten, nullptr) == 0)
        {
            REPORT_AND_RETURN_WIN32("CopyFileByHandle: Error writing target file", GetLastError());
        }
    }

    if (FlushFileBuffers(TargetHandle) == 0)
    {
        REPORT_AND_RETURN_WIN32("CopyFileByHandle: Error flushing target file", GetLastError());
    }
    if (SetEndOfFile(TargetHandle) == 0)
    {
        REPORT_AND_RETURN_WIN32("CopyFileByHandle: Error setting EoF on target file", GetLastError());
    }

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::OverwriteFileContentsWithPattern(
    handle_t FileHandle,
    std::span<const uint8_t> Pattern)
{
    uint64_t targetSize;
    if (FAILED(Utils::GetFileSize(FileHandle, targetSize)))
    {
        REPORT_AND_RETURN_WIN32("OverwriteFileContentsWithPattern: Error getting file size", GetLastError());
    }
    HRESULT hr = SetFilePointer(FileHandle, 0, FILE_BEGIN);
    if (FAILED(hr))
    {
        REPORT_AND_RETURN_HR("OverwriteFileContentsWithPattern: Error setting file pointer", hr);
    }

    uint64_t bytesRemaining = targetSize; 
    std::vector<uint8_t> buffer;
    if (bytesRemaining > MaxFileBuffer)
    {
        buffer.resize(MaxFileBuffer);
        hr = FillBufferWithPattern(buffer, Pattern);
        if (FAILED(hr))
        {
            REPORT_AND_RETURN_HR("OverwriteFileContentsWithPattern: Error in FillBufferWithPattern()", hr);
        }
    }
    else
    {
        buffer.resize(SCAST(size_t)(bytesRemaining));
        hr = FillBufferWithPattern(buffer, Pattern);
        if (FAILED(hr))
        {
            REPORT_AND_RETURN_HR("OverwriteFileContentsWithPattern: Error in FillBufferWithPattern()", hr);
        }
    }

    while (bytesRemaining > 0)
    {
        if (bytesRemaining < buffer.size())
        {
            buffer.resize(SCAST(size_t)(bytesRemaining));
            hr = FillBufferWithPattern(buffer, Pattern);
            if (FAILED(hr))
            {
                REPORT_AND_RETURN_HR("OverwriteFileContentsWithPattern: Error in FillBufferWithPattern()", hr);
            }
        }

        DWORD bytesWritten = 0;
        if (WriteFile(FileHandle, buffer.data(), SCAST(DWORD)(buffer.size()), &bytesWritten, nullptr) == 0)
        {
            REPORT_AND_RETURN_WIN32("OverwriteFileContentsWithPattern: Error writing to file", GetLastError());
        }

        bytesRemaining -= bytesWritten;
    }

    if (FlushFileBuffers(FileHandle) == 0)
    {
        REPORT_AND_RETURN_WIN32("OverwriteFileContentsWithPattern: Error flushing file", GetLastError());
    }

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::OverwriteFileAfterWithPattern(
    handle_t FileHandle,
    uint64_t FileOffset,
    std::span<const uint8_t> Pattern,
    uint32_t& WrittenBytes)
{
    WrittenBytes = 0;

    uint64_t targetSize;
    if (FAILED(Utils::GetFileSize(FileHandle, targetSize)))
    {
        REPORT_AND_RETURN_WIN32("OverwriteFileAfterWithPattern: Error getting file size", GetLastError());
    }

    if (FileOffset >= targetSize)
    {
        REPORT_AND_RETURN_WIN32("OverwriteFileAfterWithPattern: FileOffset cannot be greater than targetSize", ERROR_INVALID_PARAMETER);
    }

    HRESULT hr = SetFilePointer(FileHandle, FileOffset, FILE_BEGIN);
    if (FAILED(hr))
    {
        REPORT_AND_RETURN_HR("OverwriteFileAfterWithPattern: Error setting file pointer", hr);
    }

    uint64_t bytesRemaining;
    bytesRemaining = (targetSize - FileOffset);
    std::vector<uint8_t> buffer;
    if (bytesRemaining > MaxFileBuffer)
    {
        buffer.resize(MaxFileBuffer);
        hr = FillBufferWithPattern(buffer, Pattern);
        if (FAILED(hr))
        {
            REPORT_AND_RETURN_HR("OverwriteFileAfterWithPattern: Error in FillBufferWithPattern()", hr);
        }
    }
    else
    {
        buffer.resize(SCAST(size_t)(bytesRemaining));
        hr = FillBufferWithPattern(buffer, Pattern);
        if (FAILED(hr))
        {
            REPORT_AND_RETURN_HR("OverwriteFileAfterWithPattern: Error in FillBufferWithPattern()", hr);
        }
    }

    while (bytesRemaining > 0)
    {
        DWORD bytesWritten = 0;

        if (bytesRemaining < buffer.size())
        {
            buffer.resize(SCAST(size_t)(bytesRemaining));
            hr = FillBufferWithPattern(buffer, Pattern);
            if (FAILED(hr))
            {
                REPORT_AND_RETURN_HR("OverwriteFileAfterWithPattern: Error in FillBufferWithPattern()", hr);
            }
        }

        if (WriteFile(FileHandle, buffer.data(), SCAST(DWORD)(buffer.size()), &bytesWritten, nullptr) == 0)
        {
            REPORT_AND_RETURN_WIN32("OverwriteFileAfterWithPattern: Error writing to file", GetLastError());
        }

        bytesRemaining -= bytesWritten;
        WrittenBytes += bytesWritten;
    }

    if (FlushFileBuffers(FileHandle) == 0)
    {
        REPORT_AND_RETURN_WIN32("OverwriteFileAfterWithPattern: Error flushing file", GetLastError());
    }

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::ExtendFileSecurityDirectory(
    handle_t FileHandle,
    uint32_t ExtendedBy)
{
    uint64_t targetSize;
    if (FAILED(Utils::GetFileSize(FileHandle, targetSize)))
    {
        REPORT_AND_RETURN_WIN32("ExtendFileSecurityDirectory: Error getting file size", GetLastError());
    }

    ULARGE_INTEGER mappingSize;
    mappingSize.QuadPart = targetSize;
    MappingHandle mapping;
    mapping.get() = CreateFileMappingW(FileHandle,
                                        nullptr,
                                        PAGE_READWRITE,
                                        mappingSize.HighPart,
                                        mappingSize.LowPart,
                                        nullptr);
    if (!mapping.valid())
    {
        REPORT_AND_RETURN_WIN32("ExtendFileSecurityDirectory: Error creating file mapping", GetLastError());
    }

    mapping.view() = MapViewOfFile(mapping.get(),
                                FILE_MAP_READ | FILE_MAP_WRITE,
                                0,
                                0,
                                mappingSize.LowPart);
    if (mapping.view() == nullptr)
    {
        REPORT_AND_RETURN_WIN32("ExtendFileSecurityDirectory: Error returned by MapViewOfFile()", GetLastError());
    }

    auto dosHeader = RCAST(PIMAGE_DOS_HEADER)(mapping.view());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        //
        // This is not a PE file, we're done.
        //
        REPORT_AND_RETURN_WIN32("ExtendFileSecurityDirectory: Failed parse PE file", ERROR_INVALID_IMAGE_HASH);
    }

    auto ntHeader = RCAST(PIMAGE_NT_HEADERS32)(Add2Ptr(mapping.view(), dosHeader->e_lfanew));
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        REPORT_AND_RETURN_WIN32("ExtendFileSecurityDirectory: Failed parse PE NT Header (x32)", ERROR_INVALID_IMAGE_HASH);
    }

    IMAGE_DATA_DIRECTORY* secDir;
    if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        if (ntHeader->OptionalHeader.NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_SECURITY)
        {
            //
            // No security directory, we're done.
            //
            return S_OK;
        }
        secDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    }
    else if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        auto ntHeader64 = RCAST(PIMAGE_NT_HEADERS64)(ntHeader);
        if (ntHeader64->OptionalHeader.NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_SECURITY)
        {
            //
            // No security directory, we're done.
            //
            return S_OK;
        }
        secDir = &ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    }
    else
    {
        REPORT_AND_RETURN_WIN32("ExtendFileSecurityDirectory: Failed parse PE NT Header (x64)", ERROR_INVALID_IMAGE_HASH);
    }

    if ((secDir->VirtualAddress) == 0 || (secDir->Size == 0))
    {
        //
        // No security directory, we're done.
        //
        return S_OK;
    }

    //
    // Extend the security directory size.
    //
    secDir->Size = (secDir->Size + ExtendedBy);

    if (FlushViewOfFile(mapping.view(), mappingSize.LowPart) == 0)
    {
        DWORD lastError = GetLastError();
        REPORT_AND_RETURN_WIN32("ExtendFileSecurityDirectory: Error flushing view of file", lastError);
    }

    mapping.close();

    if (FlushFileBuffers(FileHandle) == 0)
    {
        REPORT_AND_RETURN_WIN32("ExtendFileSecurityDirectory: Error flushing file", GetLastError());
    }

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::GetImageEntryPointRva(
    handle_t FileHandle,
    uint32_t& EntryPointRva)
{
    EntryPointRva = 0;

    uint64_t fileSize;
    if (FAILED(Utils::GetFileSize(FileHandle, fileSize)))
    {
        REPORT_AND_RETURN_WIN32("ImageEntryPointRva: Error getting file size", GetLastError());
    }

    ULARGE_INTEGER mappingSize;
    mappingSize.QuadPart = fileSize;
    MappingHandle mapping;
    mapping.get() = CreateFileMappingW(FileHandle,
                                nullptr,
                                PAGE_READONLY,
                                mappingSize.HighPart,
                                mappingSize.LowPart,
                                nullptr);
    if (!mapping.valid())
    {
        REPORT_AND_RETURN_WIN32("ImageEntryPointRva: Error creating file mapping", GetLastError());
    }

    mapping.view() = MapViewOfFile(mapping.get(),
                            FILE_MAP_READ,
                            0,
                            0,
                            mappingSize.LowPart);
    if (mapping.view() == nullptr)
    {
        REPORT_AND_RETURN_WIN32("ImageEntryPointRva: Error returned by MapViewOfFile()", GetLastError());
    }

    auto dosHeader = RCAST(PIMAGE_DOS_HEADER)(mapping.view());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        REPORT_AND_RETURN_WIN32("ImageEntryPointRva: Failed parse PE file", ERROR_INVALID_IMAGE_HASH);
    }

    auto ntHeader = RCAST(PIMAGE_NT_HEADERS32)(Add2Ptr(mapping.view(), dosHeader->e_lfanew));
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        REPORT_AND_RETURN_WIN32("ImageEntryPointRva: Failed parse PE NT Header (x32)", ERROR_INVALID_IMAGE_HASH);
    }

    if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        EntryPointRva = ntHeader->OptionalHeader.AddressOfEntryPoint;
    }
    else if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        auto ntHeader64 = RCAST(PIMAGE_NT_HEADERS64)(ntHeader);
        EntryPointRva = ntHeader64->OptionalHeader.AddressOfEntryPoint;
    }
    else
    {
        REPORT_AND_RETURN_WIN32("ImageEntryPointRva: Failed parse PE NT Header (x64)", ERROR_INVALID_IMAGE_HASH);
    }

    mapping.close();

    return S_OK;
}

class OptionalUnicodeStringHelper
{
public:

    OptionalUnicodeStringHelper(
        _In_opt_ const std::optional<std::wstring>& String) :
        m_String(String)
    {
        if (m_String.has_value())
        {
            RtlInitUnicodeString(&m_Unicode, m_String->c_str());
        }
        else
        {
            RtlInitUnicodeString(&m_Unicode, L"");
        }
    }

    PUNICODE_STRING Get()
    {
        if (m_String.has_value())
        {
            return &m_Unicode;
        }
        return nullptr;
    }

    operator PUNICODE_STRING()
    {
        return Get();
    }

private:

    const std::optional<std::wstring>& m_String;
    UNICODE_STRING m_Unicode;

};

_Use_decl_annotations_
HRESULT Utils::WriteRemoteProcessParameters(
    handle_t ProcessHandle,
    const std::wstring ImageFileName,
    const std::optional<std::wstring>& DllPath,
    const std::optional<std::wstring>& CurrentDirectory,
    const std::optional<std::wstring>& CommandLine,
    void* EnvironmentBlock,
    const std::optional<std::wstring>& WindowTitle,
    const std::optional<std::wstring>& DesktopInfo,
    const std::optional<std::wstring>& ShellInfo,
    const std::optional<std::wstring>& RuntimeData)
{
    //
    // Get the basic info for the remote PEB address.
    //
    PROCESS_BASIC_INFORMATION pbi{};
    NTSTATUS status = NtQueryInformationProcess(ProcessHandle,
                                                ProcessBasicInformation,
                                                &pbi,
                                                sizeof(pbi),
                                                nullptr);
    if (!NT_SUCCESS(status))
    {
        REPORT_AND_RETURN_NT("WriteRemoteProcessParameters: Failed to query process info", status);
    }

    //
    // Generate the process parameters to write into the process.
    //
    UNICODE_STRING imageName;
    RtlInitUnicodeString(&imageName, ImageFileName.c_str());
    OptionalUnicodeStringHelper dllPath(DllPath);
    OptionalUnicodeStringHelper commandLine(CommandLine);
    OptionalUnicodeStringHelper currentDirectory(CurrentDirectory);
    OptionalUnicodeStringHelper windowTitle(WindowTitle);
    OptionalUnicodeStringHelper desktopInfo(DesktopInfo);
    OptionalUnicodeStringHelper shellInfo(ShellInfo);
    OptionalUnicodeStringHelper runtimeData(RuntimeData);
    PRTL_USER_PROCESS_PARAMETERS params;

    //
    // Generate the process parameters and do not pass
    // RTL_USER_PROC_PARAMS_NORMALIZED, this will keep the process parameters
    // de-normalized (pointers will be offsets instead of addresses) then 
    // LdrpInitializeProcess will call RtlNormalizeProcessParameters and fix
    // them up when the process starts.
    //
    // Note: There is an exception here, the Environment pointer is not
    // de-normalized - we'll fix that up ourself.
    //
    status = RtlCreateProcessParametersEx(&params,
                                          &imageName,
                                          dllPath,
                                          currentDirectory,
                                          commandLine,
                                          EnvironmentBlock,
                                          windowTitle,
                                          desktopInfo,
                                          shellInfo,
                                          runtimeData,
                                          0);
    if (!NT_SUCCESS(status))
    {
        REPORT_AND_RETURN_NT("WriteRemoteProcessParameters: Failed to create process parameters", status);
    }

    //
    // Calculate the required length.
    //
    size_t len = params->MaximumLength + params->EnvironmentSize;

    //
    // Allocate memory in the remote process to hold the process parameters.
    //
    auto remoteMemory = VirtualAllocEx(ProcessHandle,
                                       nullptr,
                                       len,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    if (remoteMemory == nullptr)
    {
        RtlDestroyProcessParameters(params);
        REPORT_AND_RETURN_WIN32("WriteRemoteProcessParameters: Error allocating memory", GetLastError());
    }


    //
    // Okay we have some memory in the remote process, go do the final fix-ups.
    //
    if (params->Environment != nullptr)
    {
        //
        // The environment block will always be right after the length, which
        // is the size of RTL_USER_PROCESS_PARAMETERS plus any extra field
        // data.
        //
        params->Environment = Add2Ptr(remoteMemory, params->Length);
    }

    //
    // Write the parameters into the remote process.
    //
    if (WriteProcessMemory(ProcessHandle, remoteMemory, params, len, nullptr) == 0)
    {
        RtlDestroyProcessParameters(params);
        REPORT_AND_RETURN_WIN32("WriteRemoteProcessParameters: Error writting parameters into the remote process", GetLastError());
    }

    //
    // Write the parameter pointer to the remote process PEB.
    //
    if (WriteProcessMemory(ProcessHandle,
                           Add2Ptr(pbi.PebBaseAddress,
                               FIELD_OFFSET(PEB, ProcessParameters)),
                           &remoteMemory,
                           sizeof(remoteMemory),
                           nullptr) == 0)
    {
        RtlDestroyProcessParameters(params);
        REPORT_AND_RETURN_WIN32("WriteRemoteProcessParameters: Error writting the parameter pointer to the remote process PEB", GetLastError());
    }

    return S_OK;
}

#pragma optimize( "", off )
_Use_decl_annotations_
BOOL Utils::ShouldReplaceWithFile(
    const char* fileName)
{
    return (fileName[0] == '\0') ? FALSE : TRUE;
}
#pragma optimize( "", on )

_Use_decl_annotations_
HRESULT Utils::GetFileName(
    const char* sourceFileName,
    std::wstring& finalFileName)
{
    size_t cbTargetFileName = strnlen_s(sourceFileName, FILE_MAX_PATH);
    int sizeNeeded = MultiByteToWideChar(CP_UTF8,
                                         0,
                                         sourceFileName,
                                         (int)cbTargetFileName,
                                         NULL,
                                         0);
    if (sizeNeeded == 0)
    {
        REPORT_AND_RETURN_WIN32("GetFileName: Error getting required size to convert filename to wide chars", GetLastError());
    }

    std::wstring TargetFileNameTmp(sizeNeeded, 0);
    if (MultiByteToWideChar(CP_UTF8,
                            0,
                            sourceFileName,
                            (int)cbTargetFileName,
                            &TargetFileNameTmp[0],
                            sizeNeeded) == 0)
    {
        REPORT_AND_RETURN_WIN32("GetFileName: Error converting filename to wide chars", GetLastError());
    }

    sizeNeeded = ExpandEnvironmentStringsW(TargetFileNameTmp.c_str(), NULL, 0);
    if (sizeNeeded == 0)
    {
        REPORT_AND_RETURN_WIN32("GetFileName: Error getting required size to expand filename", GetLastError());
    }

    finalFileName.resize(((size_t)sizeNeeded) - 1, 0);
    if (ExpandEnvironmentStringsW(TargetFileNameTmp.c_str(), &finalFileName[0], sizeNeeded) == 0)
    {
        REPORT_AND_RETURN_WIN32("GetFileName: Error expanding filename", GetLastError());
    }

    return S_OK;
}

#ifndef _WIN64
//
// Only needed for 32-bit Windows
//
_Use_decl_annotations_
HRESULT Utils::GetFileVersion(LPCWSTR lptstrFilename, PFILE_VERSION ver)
{
    DWORD dwHandle;
    DWORD dwLen = GetFileVersionInfoSizeW(lptstrFilename, &dwHandle);
    if (dwLen == 0)
    {
        REPORT_AND_RETURN_WIN32("GetFileVersion: Error getting file version info size", GetLastError());
    }
    LPVOID lpData = new LPVOID[dwLen];
    if (!GetFileVersionInfoW(lptstrFilename, 0, dwLen, lpData))
    {
        delete[] lpData;
        REPORT_AND_RETURN_WIN32("GetFileVersion: Error getting file version info", GetLastError());
    }
    VS_FIXEDFILEINFO* versionInfo;
    UINT uLen;
    if (!VerQueryValueW(lpData, L"\\", (LPVOID*)&versionInfo, &uLen))
    {
        delete[] lpData;
        REPORT_AND_RETURN_WIN32("GetFileVersion: Error getting version info", GetLastError());
    }

    ver->MajorVersion = (versionInfo->dwProductVersionMS >> 16) & 0xFFFF;
    ver->MinorVersion = versionInfo->dwProductVersionMS & 0xFFFF;
    ver->BuildVersion = (versionInfo->dwProductVersionLS >> 16) & 0xFFFF;
    ver->RevisionVersion = versionInfo->dwProductVersionLS & 0xFFFF;

    delete[] lpData;

    return S_OK;
}

_Use_decl_annotations_
HRESULT Utils::IsBuggyKernel()
{
    std::wstring kernelFile;
    HRESULT hr = Utils::GetFileName("%SystemRoot%\\System32\\ntoskrnl.exe", kernelFile);
    if (FAILED(hr))
    {
        REPORT_AND_RETURN_HR("Failed to retrieve the target filename", hr);
    }

    FileHandle kernelHandle(kernelFile);
    kernelHandle.get() = CreateFileW(kernelFile.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (!kernelHandle.valid())
    {
        REPORT_AND_RETURN_WIN32("BuggyKernel: Failed to open Kernel file", GetLastError());
    }

    FILE_VERSION ver;
    hr = GetFileVersion(kernelFile.c_str(), &ver);
    if (FAILED(hr))
    {
        REPORT_AND_RETURN_HR("BuggyKernel: Failed getting file version", hr);
    }
    dprintf("Version of %S is %hu.%hu.%hu.%hu",
        kernelFile.c_str(),
        ver.MajorVersion,
        ver.MinorVersion,
        ver.BuildVersion,
        ver.RevisionVersion
    );
    if (ver.MajorVersion == 10 &&
        ver.MinorVersion == 0 &&
        ver.BuildVersion > 10240 &&
        ver.BuildVersion < 16299)
    {
        return S_OK;
    }

    return S_FALSE;
}
#endif
