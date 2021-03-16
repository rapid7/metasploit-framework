#pragma once

namespace Utils 
{
    constexpr static uint32_t MaxFileBuffer{ 0x8000 }; // 32kib

#pragma warning(push)
#pragma warning(disable : 4634)  // xmldoc: discarding XML document comment for invalid target 
    /// <summary>
    /// Removes all occurrences of a set of values from an object.
    /// </summary>
    /// <typeparam name="T">
    /// Object type to remove elements of. Must implement erase, be forward 
    /// iterate-able, and contained value type must be move assignable.
    /// </typeparam>
    /// <param name="Object">
    /// Object to erase elements from.
    /// </param>
    /// <param name="Values">
    /// Values to remove.
    /// </param>
    template <typename T>
    void EraseAll(
        _Inout_ T& Object,
        _In_ const std::initializer_list<typename T::value_type>& Values)
    {
        for (const auto& value : Values)
        {
            Object.erase(std::remove(Object.begin(),
                                     Object.end(),
                                     value),
                         Object.end());
        }
    }
#pragma warning(pop)

    /// <summary>
    /// Formats an error code as a string.
    /// </summary>
    /// <param name="Error">
    /// Error code to format as a string.
    /// </param>
    /// <returns>
    /// Human readable string for the error code if the error is unknown a 
    /// string is returned formatted as "[number] - Unknown Error".
    /// </returns>
    std::wstring FormatError(_In_ uint32_t Error);

    /// <summary>
    /// Generates a buffer of a given length containing a supplied pattern.
    /// </summary>
    /// <param name="Buffer">
    /// Buffer to fill with the patter, must not be empty.
    /// </param>
    /// <param name="Pattern">
    /// Pattern to write into the buffer.
    /// </param>
    /// <returns>
    /// Success when the buffer is filled with the pattern. Failure if Buffer 
    /// is empty.
    /// </returns>
    _Must_inspect_result_ HRESULT FillBufferWithPattern(
        _Inout_ std::vector<uint8_t>& Buffer,
        _In_ std::span<const uint8_t> Pattern);

    /// <summary>
    /// Gets a file size.
    /// </summary>
    /// <param name="FileHandle">
    /// File to get the size of.
    /// </param>
    /// <param name="FileSize">
    /// Set to the size of the file on success.
    /// </param>
    /// <returns>
    /// Success if the file size of retrieved.
    /// </returns>
    _Must_inspect_result_ HRESULT GetFileSize(
        _In_ handle_t FileHandle, 
        _Out_ uint64_t& FileSize);

    /// <summary>
    /// Sets a file pointer.
    /// </summary>
    /// <param name="FileHandle">
    /// File to set the pointer of.
    /// </param>
    /// <param name="DistanceToMove">
    /// Distance to move the file pointer.
    /// </param>
    /// <param name="MoveMethod">
    /// Move method to use (FILE_BEGIN, FILE_CURRENT, FILE_END).
    /// </param>
    /// <returns>
    /// Success if the file pointer was set (or was already set).
    /// </returns>
    _Must_inspect_result_ HRESULT SetFilePointer(
        _In_ handle_t FileHandle,
        _In_ int64_t DistanceToMove,
        _In_ uint32_t MoveMethod);

    /// <summary>
    /// Copies the contents for a source file to the target by handle.
    /// </summary>
    /// <param name="SourceHandle">
    /// Source file handle.
    /// </param>
    /// <param name="TargetHandle">
    /// Target file handle.
    /// </param>
    /// <returns>
    /// Success if the source file has been copied to the target.
    /// </returns>
    _Must_inspect_result_ HRESULT CopyFileByHandle(
        _In_ handle_t SourceHandle, 
        _In_ handle_t TargetHandle);

    /// <summary>
    /// Overwrites the contents of a file with a pattern.
    /// </summary>
    /// <param name="FileHandle">
    /// Target file to overwrite.
    /// </param>
    /// <param name="Pattern">
    /// Pattern write over the file content.
    /// </param>
    /// <param name="PatternLength">
    /// Length of Pattern buffer.
    /// </param>
    /// <returns>
    /// Success if the file content was overwritten.
    /// </returns>
    _Must_inspect_result_ HRESULT OverwriteFileContentsWithPattern(
        _In_ handle_t FileHandle,
        _In_ std::span<const uint8_t> Pattern);

    /// <summary>
    /// Overwrites a file from a given offset with a pattern.
    /// </summary>
    /// <param name="FileHandle">
    /// Target file to overwrite.
    /// </param>
    /// <param name="FileOffset">
    /// Offset to begin writing from.
    /// </param>
    /// <param name="Pattern">
    /// Pattern to use to extend the target file with.
    /// </param>
    /// <param name="WrittenBytes">
    /// Number of bytes written.
    /// </param>
    /// <returns>
    /// Success if the file was overwritten.
    /// </returns>
    _Must_inspect_result_ HRESULT OverwriteFileAfterWithPattern(
        _In_ handle_t FileHandle,
        _In_ uint64_t FileOffset,
        _In_ std::span<const uint8_t> Pattern,
        _Out_ uint32_t& WrittenBytes);
    
    /// <summary>
    /// Extends a PE file security directory by a number of bytes.
    /// </summary>
    /// <param name="FileHandle">
    /// Target file handle.
    /// </param>
    /// <param name="ExtendedBy">
    /// Number of bytes to extend the security directory by.
    /// </param>
    /// <returns>
    /// Success if the security directory was extended. Failure if the file is 
    /// not a PE file or does not have a security directory.
    /// </returns>
    _Must_inspect_result_ HRESULT ExtendFileSecurityDirectory(
        _In_ handle_t FileHandle,
        _In_ uint32_t ExtendedBy);

    /// <summary>
    /// Retrieves the image entry point RVA from a file.
    /// </summary>
    /// <param name="FileHandle">
    /// File to parse for the entry point RVA.
    /// </param>
    /// <param name="EntryPointRva">
    /// Set to the entry point RVA on success.
    /// </param>
    /// <returns>
    /// Success if the PE image entry RVA is located.
    /// </returns>
    _Must_inspect_result_ HRESULT GetImageEntryPointRva(
        _In_ handle_t FileHandle,
        _Out_ uint32_t& EntryPointRva);

    /// <summary>
    /// Writes remote process parameters into target process.
    /// </summary>
    /// <param name="ProcessHandle">
    /// Process to write parameters into.
    /// </param>
    /// <param name="DllPath">
    /// Dll path to write into the parameters, optional.
    /// </param>
    /// <param name="ImageFileName">
    /// Image file name to write into the parameters.
    /// </param>
    /// <param name="CurrentDirectory">
    /// Current directory to write into the parameters, optional.
    /// </param>
    /// <param name="CommandLine">
    /// Command line to write into the parameters, optional.
    /// </param>
    /// <param name="EnvironmentBlock">
    /// Environment block to write into the parameters, optional.
    /// </param>
    /// <param name="WindowTitle">
    /// Window title to write into the parameters, optional.
    /// </param>
    /// <param name="DesktopInfo">
    /// Desktop info to write into the parameters, optional.
    /// </param>
    /// <param name="ShellInfo">
    /// ShellInfo to write into the parameters, optional.
    /// </param>
    /// <param name="RuntimeData">
    /// Runtime data to write into the parameters, optional.
    /// </param>
    /// <returns>
    /// Success if the remote process parameters are written.
    /// </returns>
    _Must_inspect_result_ HRESULT WriteRemoteProcessParameters(
        _In_ handle_t ProcessHandle,
        _In_ const std::wstring ImageFileName,
        _In_opt_ const std::optional<std::wstring>& DllPath,
        _In_opt_ const std::optional<std::wstring>& CurrentDirectory,
        _In_opt_ const std::optional<std::wstring>& CommandLine,
        _In_opt_ void* EnvironmentBlock,
        _In_opt_ const std::optional<std::wstring>& WindowTitle,
        _In_opt_ const std::optional<std::wstring>& DesktopInfo,
        _In_opt_ const std::optional<std::wstring>& ShellInfo,
        _In_opt_ const std::optional<std::wstring>& RuntimeData);

    _Must_inspect_result_ BOOL ShouldReplaceWithFile(
        _In_ const char* fileName);

    _Must_inspect_result_ HRESULT GetFileName(
        _In_  const char* sourceFileName,
        _Out_ std::wstring& finalFileName);

#ifndef _WIN64
    //
    // Only needed for 32-bit Windows
    //
    typedef struct _FILE_VERSION
    {
        WORD MajorVersion;
        WORD MinorVersion;
        WORD BuildVersion;
        WORD RevisionVersion;
    } FILE_VERSION, * PFILE_VERSION;

    _Must_inspect_result_ HRESULT GetFileVersion(
        _In_ LPCWSTR lptstrFilename,
        _Out_ PFILE_VERSION ver);

    _Must_inspect_result_ HRESULT IsBuggyKernel();
#endif
}