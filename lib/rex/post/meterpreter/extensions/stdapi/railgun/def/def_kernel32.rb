# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_kernel32

  def self.create_dll(dll_path = 'kernel32')
    dll = DLL.new(dll_path, ApiConstants.manager)

    dll.add_function( 'GetConsoleWindow', 'LPVOID',[])

    dll.add_function( 'ActivateActCtx', 'BOOL',[
      ["HANDLE","hActCtx","inout"],
      ["PBLOB","lpCookie","out"],
      ])

    dll.add_function( 'AddAtomA', 'WORD',[
      ["PCHAR","lpString","in"],
      ])

    dll.add_function( 'AddAtomW', 'WORD',[
      ["PWCHAR","lpString","in"],
      ])

    dll.add_function( 'AddRefActCtx', 'VOID',[
      ["HANDLE","hActCtx","inout"],
      ])

    dll.add_function( 'AddVectoredContinueHandler', 'LPVOID',[
      ["DWORD","First","in"],
      ["PBLOB","Handler","in"],
      ])

    dll.add_function( 'AddVectoredExceptionHandler', 'LPVOID',[
      ["DWORD","First","in"],
      ["PBLOB","Handler","in"],
      ])

    dll.add_function( 'AllocateUserPhysicalPages', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PBLOB","NumberOfPages","inout"],
      ["PBLOB","PageArray","out"],
      ])

    dll.add_function( 'AreFileApisANSI', 'BOOL',[
      ])

    dll.add_function( 'AssignProcessToJobObject', 'BOOL',[
      ["HANDLE","hJob","in"],
      ["HANDLE","hProcess","in"],
      ])

    dll.add_function( 'BackupRead', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpBuffer","out"],
      ["DWORD","nNumberOfBytesToRead","in"],
      ["PDWORD","lpNumberOfBytesRead","out"],
      ["BOOL","bAbort","in"],
      ["BOOL","bProcessSecurity","in"],
      ["PBLOB","lpContext","inout"],
      ])

    dll.add_function( 'BackupSeek', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["DWORD","dwLowBytesToSeek","in"],
      ["DWORD","dwHighBytesToSeek","in"],
      ["PDWORD","lpdwLowByteSeeked","out"],
      ["PDWORD","lpdwHighByteSeeked","out"],
      ["PBLOB","lpContext","inout"],
      ])

    dll.add_function( 'BackupWrite', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpBuffer","in"],
      ["DWORD","nNumberOfBytesToWrite","in"],
      ["PDWORD","lpNumberOfBytesWritten","out"],
      ["BOOL","bAbort","in"],
      ["BOOL","bProcessSecurity","in"],
      ["PBLOB","lpContext","inout"],
      ])

    dll.add_function( 'Beep', 'BOOL',[
      ["DWORD","dwFreq","in"],
      ["DWORD","dwDuration","in"],
      ])

    dll.add_function( 'BeginUpdateResourceA', 'DWORD',[
      ["PCHAR","pFileName","in"],
      ["BOOL","bDeleteExistingResources","in"],
      ])

    dll.add_function( 'BeginUpdateResourceW', 'DWORD',[
      ["PWCHAR","pFileName","in"],
      ["BOOL","bDeleteExistingResources","in"],
      ])

    dll.add_function( 'BindIoCompletionCallback', 'BOOL',[
      ["DWORD","FileHandle","in"],
      ["PBLOB","Function","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function( 'BuildCommDCBA', 'BOOL',[
      ["PCHAR","lpDef","in"],
      ["PBLOB","lpDCB","out"],
      ])

    dll.add_function( 'BuildCommDCBAndTimeoutsA', 'BOOL',[
      ["PCHAR","lpDef","in"],
      ["PBLOB","lpDCB","out"],
      ["PBLOB","lpCommTimeouts","out"],
      ])

    dll.add_function( 'BuildCommDCBAndTimeoutsW', 'BOOL',[
      ["PWCHAR","lpDef","in"],
      ["PBLOB","lpDCB","out"],
      ["PBLOB","lpCommTimeouts","out"],
      ])

    dll.add_function( 'BuildCommDCBW', 'BOOL',[
      ["PWCHAR","lpDef","in"],
      ["PBLOB","lpDCB","out"],
      ])

    dll.add_function( 'CallNamedPipeA', 'BOOL',[
      ["PCHAR","lpNamedPipeName","in"],
      ["PBLOB","lpInBuffer","in"],
      ["DWORD","nInBufferSize","in"],
      ["PBLOB","lpOutBuffer","out"],
      ["DWORD","nOutBufferSize","in"],
      ["PDWORD","lpBytesRead","out"],
      ["DWORD","nTimeOut","in"],
      ])

    dll.add_function( 'CallNamedPipeW', 'BOOL',[
      ["PWCHAR","lpNamedPipeName","in"],
      ["PBLOB","lpInBuffer","in"],
      ["DWORD","nInBufferSize","in"],
      ["PBLOB","lpOutBuffer","out"],
      ["DWORD","nOutBufferSize","in"],
      ["PDWORD","lpBytesRead","out"],
      ["DWORD","nTimeOut","in"],
      ])

    dll.add_function( 'CancelDeviceWakeupRequest', 'BOOL',[
      ["HANDLE","hDevice","in"],
      ])

    dll.add_function( 'CancelIo', 'BOOL',[
      ["HANDLE","hFile","in"],
      ])

    dll.add_function( 'CancelTimerQueueTimer', 'BOOL',[
      ["DWORD","TimerQueue","in"],
      ["DWORD","Timer","in"],
      ])

    dll.add_function( 'CancelWaitableTimer', 'BOOL',[
      ["HANDLE","hTimer","in"],
      ])

    dll.add_function( 'ChangeTimerQueueTimer', 'BOOL',[
      ["DWORD","TimerQueue","in"],
      ["DWORD","Timer","inout"],
      ["DWORD","DueTime","in"],
      ["DWORD","Period","in"],
      ])

    dll.add_function( 'CheckNameLegalDOS8Dot3A', 'BOOL',[
      ["PCHAR","lpName","in"],
      ["PCHAR","lpOemName","out"],
      ["DWORD","OemNameSize","in"],
      ["PBLOB","pbNameContainsSpaces","out"],
      ["PBLOB","pbNameLegal","out"],
      ])

    dll.add_function( 'CheckNameLegalDOS8Dot3W', 'BOOL',[
      ["PWCHAR","lpName","in"],
      ["PCHAR","lpOemName","out"],
      ["DWORD","OemNameSize","in"],
      ["PBLOB","pbNameContainsSpaces","out"],
      ["PBLOB","pbNameLegal","out"],
      ])

    dll.add_function( 'CheckRemoteDebuggerPresent', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PBLOB","pbDebuggerPresent","out"],
      ])

    dll.add_function( 'ClearCommBreak', 'BOOL',[
      ["HANDLE","hFile","in"],
      ])

    dll.add_function( 'ClearCommError', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PDWORD","lpErrors","out"],
      ["PBLOB","lpStat","out"],
      ])

    dll.add_function( 'CloseHandle', 'BOOL',[
      ["HANDLE","hObject","in"],
      ])

    dll.add_function( 'CommConfigDialogA', 'BOOL',[
      ["PCHAR","lpszName","in"],
      ["HANDLE","hWnd","in"],
      ["PBLOB","lpCC","inout"],
      ])

    dll.add_function( 'CommConfigDialogW', 'BOOL',[
      ["PWCHAR","lpszName","in"],
      ["HANDLE","hWnd","in"],
      ["PBLOB","lpCC","inout"],
      ])

    dll.add_function( 'CompareFileTime', 'DWORD',[
      ["PBLOB","lpFileTime1","in"],
      ["PBLOB","lpFileTime2","in"],
      ])

    dll.add_function( 'ConnectNamedPipe', 'BOOL',[
      ["HANDLE","hNamedPipe","in"],
      ["PBLOB","lpOverlapped","inout"],
      ])

    dll.add_function( 'ContinueDebugEvent', 'BOOL',[
      ["DWORD","dwProcessId","in"],
      ["DWORD","dwThreadId","in"],
      ["DWORD","dwContinueStatus","in"],
      ])

    dll.add_function( 'ConvertFiberToThread', 'BOOL',[
      ])

    dll.add_function( 'ConvertThreadToFiber', 'LPVOID',[
      ["PBLOB","lpParameter","in"],
      ])

    dll.add_function( 'ConvertThreadToFiberEx', 'LPVOID',[
      ["PBLOB","lpParameter","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function( 'CopyFileA', 'BOOL',[
      ["PCHAR","lpExistingFileName","in"],
      ["PCHAR","lpNewFileName","in"],
      ["BOOL","bFailIfExists","in"],
      ])

    dll.add_function( 'CopyFileExA', 'BOOL',[
      ["PCHAR","lpExistingFileName","in"],
      ["PCHAR","lpNewFileName","in"],
      ["PBLOB","lpProgressRoutine","in"],
      ["PBLOB","lpData","in"],
      ["PBLOB","pbCancel","in"],
      ["DWORD","dwCopyFlags","in"],
      ])

    dll.add_function( 'CopyFileExW', 'BOOL',[
      ["PWCHAR","lpExistingFileName","in"],
      ["PWCHAR","lpNewFileName","in"],
      ["PBLOB","lpProgressRoutine","in"],
      ["PBLOB","lpData","in"],
      ["PBLOB","pbCancel","in"],
      ["DWORD","dwCopyFlags","in"],
      ])

    dll.add_function( 'CopyFileW', 'BOOL',[
      ["PWCHAR","lpExistingFileName","in"],
      ["PWCHAR","lpNewFileName","in"],
      ["BOOL","bFailIfExists","in"],
      ])

    dll.add_function( 'CreateActCtxA', 'DWORD',[
      ["PBLOB","pActCtx","in"],
      ])

    dll.add_function( 'CreateActCtxW', 'DWORD',[
      ["PBLOB","pActCtx","in"],
      ])

    dll.add_function( 'CreateDirectoryA', 'BOOL',[
      ["PCHAR","lpPathName","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ])

    dll.add_function( 'CreateDirectoryExA', 'BOOL',[
      ["PCHAR","lpTemplateDirectory","in"],
      ["PCHAR","lpNewDirectory","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ])

    dll.add_function( 'CreateDirectoryExW', 'BOOL',[
      ["PWCHAR","lpTemplateDirectory","in"],
      ["PWCHAR","lpNewDirectory","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ])

    dll.add_function( 'CreateDirectoryW', 'BOOL',[
      ["PWCHAR","lpPathName","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ])

    dll.add_function( 'CreateEventA', 'DWORD',[
      ["PBLOB","lpEventAttributes","in"],
      ["BOOL","bManualReset","in"],
      ["BOOL","bInitialState","in"],
      ["PCHAR","lpName","in"],
      ])

    dll.add_function( 'CreateEventW', 'DWORD',[
      ["PBLOB","lpEventAttributes","in"],
      ["BOOL","bManualReset","in"],
      ["BOOL","bInitialState","in"],
      ["PWCHAR","lpName","in"],
      ])

    dll.add_function( 'CreateFiber', 'LPVOID',[
      ["DWORD","dwStackSize","in"],
      ["PBLOB","lpStartAddress","in"],
      ["PBLOB","lpParameter","in"],
      ])

    dll.add_function( 'CreateFiberEx', 'LPVOID',[
      ["DWORD","dwStackCommitSize","in"],
      ["DWORD","dwStackReserveSize","in"],
      ["DWORD","dwFlags","in"],
      ["PBLOB","lpStartAddress","in"],
      ["PBLOB","lpParameter","in"],
      ])

    dll.add_function( 'CreateFileA', 'DWORD',[
      ["PCHAR","lpFileName","in"],
      ["DWORD","dwDesiredAccess","in"],
      ["DWORD","dwShareMode","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ["DWORD","dwCreationDisposition","in"],
      ["DWORD","dwFlagsAndAttributes","in"],
      ["HANDLE","hTemplateFile","in"],
      ])

    dll.add_function( 'CreateFileMappingA', 'DWORD',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpFileMappingAttributes","in"],
      ["DWORD","flProtect","in"],
      ["DWORD","dwMaximumSizeHigh","in"],
      ["DWORD","dwMaximumSizeLow","in"],
      ["PCHAR","lpName","in"],
      ])

    dll.add_function( 'CreateFileMappingW', 'DWORD',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpFileMappingAttributes","in"],
      ["DWORD","flProtect","in"],
      ["DWORD","dwMaximumSizeHigh","in"],
      ["DWORD","dwMaximumSizeLow","in"],
      ["PWCHAR","lpName","in"],
      ])

    dll.add_function( 'CreateFileW', 'DWORD',[
      ["PWCHAR","lpFileName","in"],
      ["DWORD","dwDesiredAccess","in"],
      ["DWORD","dwShareMode","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ["DWORD","dwCreationDisposition","in"],
      ["DWORD","dwFlagsAndAttributes","in"],
      ["HANDLE","hTemplateFile","in"],
      ])

    dll.add_function( 'CreateHardLinkA', 'BOOL',[
      ["PCHAR","lpFileName","in"],
      ["PCHAR","lpExistingFileName","in"],
      ["PBLOB","lpSecurityAttributes","inout"],
      ])

    dll.add_function( 'CreateHardLinkW', 'BOOL',[
      ["PWCHAR","lpFileName","in"],
      ["PWCHAR","lpExistingFileName","in"],
      ["PBLOB","lpSecurityAttributes","inout"],
      ])

    dll.add_function( 'CreateIoCompletionPort', 'DWORD',[
      ["DWORD","FileHandle","in"],
      ["DWORD","ExistingCompletionPort","in"],
      ["PDWORD","CompletionKey","in"],
      ["DWORD","NumberOfConcurrentThreads","in"],
      ])

    dll.add_function( 'CreateJobObjectA', 'DWORD',[
      ["PBLOB","lpJobAttributes","in"],
      ["PCHAR","lpName","in"],
      ])

    dll.add_function( 'CreateJobObjectW', 'DWORD',[
      ["PBLOB","lpJobAttributes","in"],
      ["PWCHAR","lpName","in"],
      ])

    dll.add_function( 'CreateJobSet', 'BOOL',[
      ["DWORD","NumJob","in"],
      ["PBLOB","UserJobSet","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function( 'CreateMailslotA', 'DWORD',[
      ["PCHAR","lpName","in"],
      ["DWORD","nMaxMessageSize","in"],
      ["DWORD","lReadTimeout","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ])

    dll.add_function( 'CreateMailslotW', 'DWORD',[
      ["PWCHAR","lpName","in"],
      ["DWORD","nMaxMessageSize","in"],
      ["DWORD","lReadTimeout","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ])

    dll.add_function( 'CreateMemoryResourceNotification', 'DWORD',[
      ["PDWORD","NotificationType","in"],
      ])

    dll.add_function( 'CreateMutexA', 'DWORD',[
      ["PBLOB","lpMutexAttributes","in"],
      ["BOOL","bInitialOwner","in"],
      ["PCHAR","lpName","in"],
      ])

    dll.add_function( 'CreateMutexW', 'DWORD',[
      ["PBLOB","lpMutexAttributes","in"],
      ["BOOL","bInitialOwner","in"],
      ["PWCHAR","lpName","in"],
      ])

    dll.add_function( 'CreateNamedPipeA', 'DWORD',[
      ["PCHAR","lpName","in"],
      ["DWORD","dwOpenMode","in"],
      ["DWORD","dwPipeMode","in"],
      ["DWORD","nMaxInstances","in"],
      ["DWORD","nOutBufferSize","in"],
      ["DWORD","nInBufferSize","in"],
      ["DWORD","nDefaultTimeOut","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ])

    dll.add_function( 'CreateNamedPipeW', 'DWORD',[
      ["PWCHAR","lpName","in"],
      ["DWORD","dwOpenMode","in"],
      ["DWORD","dwPipeMode","in"],
      ["DWORD","nMaxInstances","in"],
      ["DWORD","nOutBufferSize","in"],
      ["DWORD","nInBufferSize","in"],
      ["DWORD","nDefaultTimeOut","in"],
      ["PBLOB","lpSecurityAttributes","in"],
      ])

    dll.add_function( 'CreatePipe', 'BOOL',[
      ["PDWORD","hReadPipe","out"],
      ["PDWORD","hWritePipe","out"],
      ["PBLOB","lpPipeAttributes","in"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'CreateProcessA', 'BOOL',[
      ["PCHAR","lpApplicationName","in"],
      ["PCHAR","lpCommandLine","inout"],
      ["PBLOB","lpProcessAttributes","in"],
      ["PBLOB","lpThreadAttributes","in"],
      ["BOOL","bInheritHandles","in"],
      ["DWORD","dwCreationFlags","in"],
      ["PBLOB","lpEnvironment","in"],
      ["PCHAR","lpCurrentDirectory","in"],
      ["PBLOB","lpStartupInfo","in"],
      ["PBLOB","lpProcessInformation","out"],
      ])

    dll.add_function( 'CreateProcessW', 'BOOL',[
      ["PWCHAR","lpApplicationName","in"],
      ["PWCHAR","lpCommandLine","inout"],
      ["PBLOB","lpProcessAttributes","in"],
      ["PBLOB","lpThreadAttributes","in"],
      ["BOOL","bInheritHandles","in"],
      ["DWORD","dwCreationFlags","in"],
      ["PBLOB","lpEnvironment","in"],
      ["PWCHAR","lpCurrentDirectory","in"],
      ["PBLOB","lpStartupInfo","in"],
      ["PBLOB","lpProcessInformation","out"],
      ])

    dll.add_function( 'CreateRemoteThread', 'DWORD',[
      ["HANDLE","hProcess","in"],
      ["PBLOB","lpThreadAttributes","in"],
      ["DWORD","dwStackSize","in"],
      ["LPVOID","lpStartAddress","in"],
      ["PBLOB","lpParameter","in"],
      ["DWORD","dwCreationFlags","in"],
      ["PDWORD","lpThreadId","out"],
      ])

    dll.add_function( 'CreateSemaphoreA', 'DWORD',[
      ["PBLOB","lpSemaphoreAttributes","in"],
      ["DWORD","lInitialCount","in"],
      ["DWORD","lMaximumCount","in"],
      ["PCHAR","lpName","in"],
      ])

    dll.add_function( 'CreateSemaphoreW', 'DWORD',[
      ["PBLOB","lpSemaphoreAttributes","in"],
      ["DWORD","lInitialCount","in"],
      ["DWORD","lMaximumCount","in"],
      ["PWCHAR","lpName","in"],
      ])

    dll.add_function( 'CreateTapePartition', 'DWORD',[
      ["HANDLE","hDevice","in"],
      ["DWORD","dwPartitionMethod","in"],
      ["DWORD","dwCount","in"],
      ["DWORD","dwSize","in"],
      ])

    dll.add_function( 'CreateThread', 'HANDLE',[
      ["PBLOB","lpThreadAttributes","in"],
      ["DWORD","dwStackSize","in"],
      ["LPVOID","lpStartAddress","in"],
      ["PBLOB","lpParameter","in"],
      ["DWORD","dwCreationFlags","in"],
      ["PDWORD","lpThreadId","out"],
      ])

    dll.add_function( 'CreateTimerQueue', 'DWORD',[
      ])

    dll.add_function( 'CreateTimerQueueTimer', 'BOOL',[
      ["PDWORD","phNewTimer","out"],
      ["DWORD","TimerQueue","in"],
      ["PBLOB","Callback","in"],
      ["PBLOB","Parameter","in"],
      ["DWORD","DueTime","in"],
      ["DWORD","Period","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function( 'CreateWaitableTimerA', 'DWORD',[
      ["PBLOB","lpTimerAttributes","in"],
      ["BOOL","bManualReset","in"],
      ["PCHAR","lpTimerName","in"],
      ])

    dll.add_function( 'CreateWaitableTimerW', 'DWORD',[
      ["PBLOB","lpTimerAttributes","in"],
      ["BOOL","bManualReset","in"],
      ["PWCHAR","lpTimerName","in"],
      ])

    dll.add_function( 'DeactivateActCtx', 'BOOL',[
      ["DWORD","dwFlags","in"],
      ["PDWORD","ulCookie","in"],
      ])

    dll.add_function( 'DebugActiveProcess', 'BOOL',[
      ["DWORD","dwProcessId","in"],
      ])

    dll.add_function( 'DebugActiveProcessStop', 'BOOL',[
      ["DWORD","dwProcessId","in"],
      ])

    dll.add_function( 'DebugBreak', 'VOID',[
      ])

    dll.add_function( 'DebugBreakProcess', 'BOOL',[
      ["DWORD","Process","in"],
      ])

    dll.add_function( 'DebugSetProcessKillOnExit', 'BOOL',[
      ["BOOL","KillOnExit","in"],
      ])

    dll.add_function( 'DecodePointer', 'LPVOID',[
      ["PBLOB","Ptr","in"],
      ])

    dll.add_function( 'DecodeSystemPointer', 'LPVOID',[
      ["PBLOB","Ptr","in"],
      ])

    dll.add_function( 'DefineDosDeviceA', 'BOOL',[
      ["DWORD","dwFlags","in"],
      ["PCHAR","lpDeviceName","in"],
      ["PCHAR","lpTargetPath","in"],
      ])

    dll.add_function( 'DefineDosDeviceW', 'BOOL',[
      ["DWORD","dwFlags","in"],
      ["PWCHAR","lpDeviceName","in"],
      ["PWCHAR","lpTargetPath","in"],
      ])

    dll.add_function( 'DeleteAtom', 'WORD',[
      ["WORD","nAtom","in"],
      ])

    dll.add_function( 'DeleteCriticalSection', 'VOID',[
      ["PBLOB","lpCriticalSection","inout"],
      ])

    dll.add_function( 'DeleteFiber', 'VOID',[
      ["PBLOB","lpFiber","in"],
      ])

    dll.add_function( 'DeleteFileA', 'BOOL',[
      ["PCHAR","lpFileName","in"],
      ])

    dll.add_function( 'DeleteFileW', 'BOOL',[
      ["PWCHAR","lpFileName","in"],
      ])

    dll.add_function( 'DeleteTimerQueue', 'BOOL',[
      ["DWORD","TimerQueue","in"],
      ])

    dll.add_function( 'DeleteTimerQueueEx', 'BOOL',[
      ["DWORD","TimerQueue","in"],
      ["DWORD","CompletionEvent","in"],
      ])

    dll.add_function( 'DeleteTimerQueueTimer', 'BOOL',[
      ["DWORD","TimerQueue","in"],
      ["DWORD","Timer","in"],
      ["DWORD","CompletionEvent","in"],
      ])

    dll.add_function( 'DeleteVolumeMountPointA', 'BOOL',[
      ["PCHAR","lpszVolumeMountPoint","in"],
      ])

    dll.add_function( 'DeleteVolumeMountPointW', 'BOOL',[
      ["PWCHAR","lpszVolumeMountPoint","in"],
      ])

    dll.add_function( 'DeviceIoControl', 'BOOL',[
      ["HANDLE","hDevice","in"],
      ["DWORD","dwIoControlCode","in"],
      ["PBLOB","lpInBuffer","in"],
      ["DWORD","nInBufferSize","in"],
      ["PBLOB","lpOutBuffer","out"],
      ["DWORD","nOutBufferSize","in"],
      ["PDWORD","lpBytesReturned","out"],
      ["PBLOB","lpOverlapped","inout"],
      ])

    dll.add_function( 'DisableThreadLibraryCalls', 'BOOL',[
      ["HANDLE","hLibModule","in"],
      ])

    dll.add_function( 'DisconnectNamedPipe', 'BOOL',[
      ["HANDLE","hNamedPipe","in"],
      ])

    dll.add_function( 'DnsHostnameToComputerNameA', 'BOOL',[
      ["PCHAR","Hostname","in"],
      ["PCHAR","ComputerName","out"],
      ["PDWORD","nSize","inout"],
      ])

    dll.add_function( 'DnsHostnameToComputerNameW', 'BOOL',[
      ["PWCHAR","Hostname","in"],
      ["PWCHAR","ComputerName","out"],
      ["PDWORD","nSize","inout"],
      ])

    dll.add_function( 'DosDateTimeToFileTime', 'BOOL',[
      ["WORD","wFatDate","in"],
      ["WORD","wFatTime","in"],
      ["PBLOB","lpFileTime","out"],
      ])

    dll.add_function( 'DuplicateHandle', 'BOOL',[
      ["HANDLE","hSourceProcessHandle","in"],
      ["HANDLE","hSourceHandle","in"],
      ["HANDLE","hTargetProcessHandle","in"],
      ["PDWORD","lpTargetHandle","out"],
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["DWORD","dwOptions","in"],
      ])

    dll.add_function( 'EncodePointer', 'LPVOID',[
      ["PBLOB","Ptr","in"],
      ])

    dll.add_function( 'EncodeSystemPointer', 'LPVOID',[
      ["PBLOB","Ptr","in"],
      ])

    dll.add_function( 'EndUpdateResourceA', 'BOOL',[
      ["HANDLE","hUpdate","in"],
      ["BOOL","fDiscard","in"],
      ])

    dll.add_function( 'EndUpdateResourceW', 'BOOL',[
      ["HANDLE","hUpdate","in"],
      ["BOOL","fDiscard","in"],
      ])

    dll.add_function( 'EnterCriticalSection', 'VOID',[
      ["PBLOB","lpCriticalSection","inout"],
      ])

    dll.add_function( 'EnumResourceLanguagesA', 'BOOL',[
      ["HANDLE","hModule","in"],
      ["PCHAR","lpType","in"],
      ["PCHAR","lpName","in"],
      ["PBLOB","lpEnumFunc","in"],
      ["PBLOB","lparam","in"],
      ])

    dll.add_function( 'EnumResourceLanguagesW', 'BOOL',[
      ["HANDLE","hModule","in"],
      ["PWCHAR","lpType","in"],
      ["PWCHAR","lpName","in"],
      ["PBLOB","lpEnumFunc","in"],
      ["PBLOB","lparam","in"],
      ])

    dll.add_function( 'EnumResourceNamesA', 'BOOL',[
      ["HANDLE","hModule","in"],
      ["PCHAR","lpType","in"],
      ["PBLOB","lpEnumFunc","in"],
      ["PBLOB","lparam","in"],
      ])

    dll.add_function( 'EnumResourceNamesW', 'BOOL',[
      ["HANDLE","hModule","in"],
      ["PWCHAR","lpType","in"],
      ["PBLOB","lpEnumFunc","in"],
      ["PBLOB","lparam","in"],
      ])

    dll.add_function( 'EnumResourceTypesA', 'BOOL',[
      ["HANDLE","hModule","in"],
      ["PBLOB","lpEnumFunc","in"],
      ["PBLOB","lparam","in"],
      ])

    dll.add_function( 'EnumResourceTypesW', 'BOOL',[
      ["HANDLE","hModule","in"],
      ["PBLOB","lpEnumFunc","in"],
      ["PBLOB","lparam","in"],
      ])

    dll.add_function( 'EnumSystemFirmwareTables', 'DWORD',[
      ["DWORD","FirmwareTableProviderSignature","in"],
      ["PBLOB","pFirmwareTableEnumBuffer","out"],
      ["DWORD","BufferSize","in"],
      ])

    dll.add_function( 'EraseTape', 'DWORD',[
      ["HANDLE","hDevice","in"],
      ["DWORD","dwEraseType","in"],
      ["BOOL","bImmediate","in"],
      ])

    dll.add_function( 'EscapeCommFunction', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["DWORD","dwFunc","in"],
      ])

    dll.add_function( 'ExitProcess', 'VOID',[
      ["DWORD","uExitCode","in"],
      ])

    dll.add_function( 'ExitThread', 'VOID',[
      ["DWORD","dwExitCode","in"],
      ])

    dll.add_function( 'ExpandEnvironmentStringsA', 'DWORD',[
      ["PCHAR","lpSrc","in"],
      ["PCHAR","lpDst","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'ExpandEnvironmentStringsW', 'DWORD',[
      ["PWCHAR","lpSrc","in"],
      ["PWCHAR","lpDst","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'FatalAppExitA', 'VOID',[
      ["DWORD","uAction","in"],
      ["PCHAR","lpMessageText","in"],
      ])

    dll.add_function( 'FatalAppExitW', 'VOID',[
      ["DWORD","uAction","in"],
      ["PWCHAR","lpMessageText","in"],
      ])

    dll.add_function( 'FatalExit', 'VOID',[
      ["DWORD","ExitCode","in"],
      ])

    dll.add_function( 'FileTimeToDosDateTime', 'BOOL',[
      ["PBLOB","lpFileTime","in"],
      ["PBLOB","lpFatDate","out"],
      ["PBLOB","lpFatTime","out"],
      ])

    dll.add_function( 'FileTimeToLocalFileTime', 'BOOL',[
      ["PBLOB","lpFileTime","in"],
      ["PBLOB","lpLocalFileTime","out"],
      ])

    dll.add_function( 'FileTimeToSystemTime', 'BOOL',[
      ["PBLOB","lpFileTime","in"],
      ["PBLOB","lpSystemTime","out"],
      ])

    dll.add_function( 'FindActCtxSectionGuid', 'BOOL',[
      ["DWORD","dwFlags","in"],
      ["PBLOB","lpExtensionGuid","inout"],
      ["DWORD","ulSectionId","in"],
      ["PBLOB","lpGuidToFind","in"],
      ["PBLOB","ReturnedData","out"],
      ])

    dll.add_function( 'FindActCtxSectionStringA', 'BOOL',[
      ["DWORD","dwFlags","in"],
      ["PBLOB","lpExtensionGuid","inout"],
      ["DWORD","ulSectionId","in"],
      ["PCHAR","lpStringToFind","in"],
      ["PBLOB","ReturnedData","out"],
      ])

    dll.add_function( 'FindActCtxSectionStringW', 'BOOL',[
      ["DWORD","dwFlags","in"],
      ["PBLOB","lpExtensionGuid","inout"],
      ["DWORD","ulSectionId","in"],
      ["PWCHAR","lpStringToFind","in"],
      ["PBLOB","ReturnedData","out"],
      ])

    dll.add_function( 'FindAtomA', 'WORD',[
      ["PCHAR","lpString","in"],
      ])

    dll.add_function( 'FindAtomW', 'WORD',[
      ["PWCHAR","lpString","in"],
      ])

    dll.add_function( 'FindClose', 'BOOL',[
      ["HANDLE","hFindFile","inout"],
      ])

    dll.add_function( 'FindCloseChangeNotification', 'BOOL',[
      ["HANDLE","hChangeHandle","in"],
      ])

    dll.add_function( 'FindFirstChangeNotificationA', 'DWORD',[
      ["PCHAR","lpPathName","in"],
      ["BOOL","bWatchSubtree","in"],
      ["DWORD","dwNotifyFilter","in"],
      ])

    dll.add_function( 'FindFirstChangeNotificationW', 'DWORD',[
      ["PWCHAR","lpPathName","in"],
      ["BOOL","bWatchSubtree","in"],
      ["DWORD","dwNotifyFilter","in"],
      ])

    dll.add_function( 'FindFirstFileA', 'DWORD',[
      ["PCHAR","lpFileName","in"],
      ["PBLOB","lpFindFileData","out"],
      ])

    dll.add_function( 'FindFirstFileExA', 'DWORD',[
      ["PCHAR","lpFileName","in"],
      ["PBLOB","fInfoLevelId","in"],
      ["PBLOB","lpFindFileData","out"],
      ["PBLOB","fSearchOp","in"],
      ["PBLOB","lpSearchFilter","inout"],
      ["DWORD","dwAdditionalFlags","in"],
      ])

    dll.add_function( 'FindFirstFileExW', 'DWORD',[
      ["PWCHAR","lpFileName","in"],
      ["PBLOB","fInfoLevelId","in"],
      ["PBLOB","lpFindFileData","out"],
      ["PBLOB","fSearchOp","in"],
      ["PBLOB","lpSearchFilter","inout"],
      ["DWORD","dwAdditionalFlags","in"],
      ])

    dll.add_function( 'FindFirstFileW', 'DWORD',[
      ["PWCHAR","lpFileName","in"],
      ["PBLOB","lpFindFileData","out"],
      ])

    dll.add_function( 'FindFirstStreamW', 'DWORD',[
      ["PWCHAR","lpFileName","in"],
      ["PBLOB","InfoLevel","in"],
      ["PBLOB","lpFindStreamData","out"],
      ["DWORD","dwFlags","inout"],
      ])

    dll.add_function( 'FindFirstVolumeA', 'DWORD',[
      ["PCHAR","lpszVolumeName","out"],
      ["DWORD","cchBufferLength","in"],
      ])

    dll.add_function( 'FindFirstVolumeMountPointA', 'DWORD',[
      ["PCHAR","lpszRootPathName","in"],
      ["PCHAR","lpszVolumeMountPoint","out"],
      ["DWORD","cchBufferLength","in"],
      ])

    dll.add_function( 'FindFirstVolumeMountPointW', 'DWORD',[
      ["PWCHAR","lpszRootPathName","in"],
      ["PWCHAR","lpszVolumeMountPoint","out"],
      ["DWORD","cchBufferLength","in"],
      ])

    dll.add_function( 'FindFirstVolumeW', 'DWORD',[
      ["PWCHAR","lpszVolumeName","out"],
      ["DWORD","cchBufferLength","in"],
      ])

    dll.add_function( 'FindNextChangeNotification', 'BOOL',[
      ["HANDLE","hChangeHandle","in"],
      ])

    dll.add_function( 'FindNextFileA', 'BOOL',[
      ["HANDLE","hFindFile","in"],
      ["PBLOB","lpFindFileData","out"],
      ])

    dll.add_function( 'FindNextFileW', 'BOOL',[
      ["HANDLE","hFindFile","in"],
      ["PBLOB","lpFindFileData","out"],
      ])

    dll.add_function( 'FindNextStreamW', 'BOOL',[
      ["HANDLE","hFindStream","in"],
      ["PBLOB","lpFindStreamData","out"],
      ])

    dll.add_function( 'FindNextVolumeA', 'BOOL',[
      ["HANDLE","hFindVolume","inout"],
      ["PCHAR","lpszVolumeName","out"],
      ["DWORD","cchBufferLength","in"],
      ])

    dll.add_function( 'FindNextVolumeMountPointA', 'BOOL',[
      ["HANDLE","hFindVolumeMountPoint","in"],
      ["PCHAR","lpszVolumeMountPoint","out"],
      ["DWORD","cchBufferLength","in"],
      ])

    dll.add_function( 'FindNextVolumeMountPointW', 'BOOL',[
      ["HANDLE","hFindVolumeMountPoint","in"],
      ["PWCHAR","lpszVolumeMountPoint","out"],
      ["DWORD","cchBufferLength","in"],
      ])

    dll.add_function( 'FindNextVolumeW', 'BOOL',[
      ["HANDLE","hFindVolume","inout"],
      ["PWCHAR","lpszVolumeName","out"],
      ["DWORD","cchBufferLength","in"],
      ])

    dll.add_function( 'FindResourceA', 'DWORD',[
      ["HANDLE","hModule","in"],
      ["PCHAR","lpName","in"],
      ["PCHAR","lpType","in"],
      ])

    dll.add_function( 'FindResourceExA', 'DWORD',[
      ["HANDLE","hModule","in"],
      ["PCHAR","lpType","in"],
      ["PCHAR","lpName","in"],
      ["WORD","wLanguage","in"],
      ])

    dll.add_function( 'FindResourceExW', 'DWORD',[
      ["HANDLE","hModule","in"],
      ["PWCHAR","lpType","in"],
      ["PWCHAR","lpName","in"],
      ["WORD","wLanguage","in"],
      ])

    dll.add_function( 'FindResourceW', 'DWORD',[
      ["HANDLE","hModule","in"],
      ["PWCHAR","lpName","in"],
      ["PWCHAR","lpType","in"],
      ])

    dll.add_function( 'FindVolumeClose', 'BOOL',[
      ["HANDLE","hFindVolume","in"],
      ])

    dll.add_function( 'FindVolumeMountPointClose', 'BOOL',[
      ["HANDLE","hFindVolumeMountPoint","in"],
      ])

    dll.add_function( 'FlsAlloc', 'DWORD',[
      ["PBLOB","lpCallback","in"],
      ])

    dll.add_function( 'FlsFree', 'BOOL',[
      ["DWORD","dwFlsIndex","in"],
      ])

    dll.add_function( 'FlsGetValue', 'LPVOID',[
      ["DWORD","dwFlsIndex","in"],
      ])

    dll.add_function( 'FlsSetValue', 'BOOL',[
      ["DWORD","dwFlsIndex","in"],
      ["PBLOB","lpFlsData","in"],
      ])

    dll.add_function( 'FlushFileBuffers', 'BOOL',[
      ["HANDLE","hFile","in"],
      ])

    dll.add_function( 'FlushInstructionCache', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PBLOB","lpBaseAddress","in"],
      ["DWORD","dwSize","in"],
      ])

    dll.add_function( 'FlushViewOfFile', 'BOOL',[
      ["PBLOB","lpBaseAddress","in"],
      ["DWORD","dwNumberOfBytesToFlush","in"],
      ])

    dll.add_function( 'FreeEnvironmentStringsA', 'BOOL',[
      ["PBLOB","param0","in"],
      ])

    dll.add_function( 'FreeEnvironmentStringsW', 'BOOL',[
      ["PBLOB","param0","in"],
      ])

    dll.add_function( 'FreeLibrary', 'BOOL',[
      ["HANDLE","hLibModule","in"],
      ])

    dll.add_function( 'FreeLibraryAndExitThread', 'VOID',[
      ["HANDLE","hLibModule","in"],
      ["DWORD","dwExitCode","in"],
      ])

    dll.add_function( 'FreeResource', 'BOOL',[
      ["HANDLE","hResData","in"],
      ])

    dll.add_function( 'FreeUserPhysicalPages', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PBLOB","NumberOfPages","inout"],
      ["PBLOB","PageArray","in"],
      ])

    dll.add_function( 'GetAtomNameA', 'DWORD',[
      ["WORD","nAtom","in"],
      ["PCHAR","lpBuffer","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'GetAtomNameW', 'DWORD',[
      ["WORD","nAtom","in"],
      ["PWCHAR","lpBuffer","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'GetBinaryTypeA', 'BOOL',[
      ["PCHAR","lpApplicationName","in"],
      ["PDWORD","lpBinaryType","out"],
      ])

    dll.add_function( 'GetBinaryTypeW', 'BOOL',[
      ["PWCHAR","lpApplicationName","in"],
      ["PDWORD","lpBinaryType","out"],
      ])

    dll.add_function( 'GetCommConfig', 'BOOL',[
      ["HANDLE","hCommDev","in"],
      ["PBLOB","lpCC","out"],
      ["PDWORD","lpdwSize","inout"],
      ])

    dll.add_function( 'GetCommMask', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PDWORD","lpEvtMask","out"],
      ])

    dll.add_function( 'GetCommModemStatus', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PDWORD","lpModemStat","out"],
      ])

    dll.add_function( 'GetCommProperties', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpCommProp","out"],
      ])

    dll.add_function( 'GetCommState', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpDCB","out"],
      ])

    dll.add_function( 'GetCommTimeouts', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpCommTimeouts","out"],
      ])

    #dll.add_function( 'GetCommandLineA', 'PCHAR',[
    #	])

    #dll.add_function( 'GetCommandLineW', 'PWCHAR',[
    #	])

    dll.add_function( 'GetCompressedFileSizeA', 'DWORD',[
      ["PCHAR","lpFileName","in"],
      ["PDWORD","lpFileSizeHigh","out"],
      ])

    dll.add_function( 'GetCompressedFileSizeW', 'DWORD',[
      ["PWCHAR","lpFileName","in"],
      ["PDWORD","lpFileSizeHigh","out"],
      ])

    dll.add_function( 'GetComputerNameA', 'BOOL',[
      ["PCHAR","lpBuffer","out"],
      ["PDWORD","nSize","inout"],
      ])

    dll.add_function( 'GetComputerNameExA', 'BOOL',[
      ["DWORD","NameType","in"],
      ["PCHAR","lpBuffer","out"],
      ["PDWORD","nSize","inout"],
      ])

    dll.add_function( 'GetComputerNameExW', 'BOOL',[
      ["DWORD","NameType","in"],
      ["PWCHAR","lpBuffer","out"],
      ["PDWORD","nSize","inout"],
      ])

    dll.add_function( 'GetComputerNameW', 'BOOL',[
      ["PWCHAR","lpBuffer","out"],
      ["PDWORD","nSize","inout"],
      ])

    dll.add_function( 'GetCurrentActCtx', 'BOOL',[
      ["PDWORD","lphActCtx","out"],
      ])

    dll.add_function( 'GetCurrentDirectoryA', 'DWORD',[
      ["DWORD","nBufferLength","in"],
      ["PCHAR","lpBuffer","out"],
      ])

    dll.add_function( 'GetCurrentDirectoryW', 'DWORD',[
      ["DWORD","nBufferLength","in"],
      ["PWCHAR","lpBuffer","out"],
      ])

    dll.add_function( 'GetCurrentProcess', 'HANDLE',[
      ])

    dll.add_function( 'GetCurrentProcessId', 'DWORD',[
      ])

    dll.add_function( 'GetCurrentProcessorNumber', 'DWORD',[
      ])

    dll.add_function( 'GetCurrentThread', 'HANDLE',[
      ])

    dll.add_function( 'GetCurrentThreadId', 'DWORD',[
      ])

    dll.add_function( 'GetDefaultCommConfigA', 'BOOL',[
      ["PCHAR","lpszName","in"],
      ["PBLOB","lpCC","out"],
      ["PDWORD","lpdwSize","inout"],
      ])

    dll.add_function( 'GetDefaultCommConfigW', 'BOOL',[
      ["PWCHAR","lpszName","in"],
      ["PBLOB","lpCC","out"],
      ["PDWORD","lpdwSize","inout"],
      ])

    dll.add_function( 'GetDevicePowerState', 'BOOL',[
      ["HANDLE","hDevice","in"],
      ["PBLOB","pfOn","out"],
      ])

    dll.add_function( 'GetDiskFreeSpaceA', 'BOOL',[
      ["PCHAR","lpRootPathName","in"],
      ["PDWORD","lpSectorsPerCluster","out"],
      ["PDWORD","lpBytesPerSector","out"],
      ["PDWORD","lpNumberOfFreeClusters","out"],
      ["PDWORD","lpTotalNumberOfClusters","out"],
      ])

    dll.add_function( 'GetDiskFreeSpaceExA', 'BOOL',[
      ["PCHAR","lpDirectoryName","in"],
      ["PBLOB","lpFreeBytesAvailableToCaller","out"],
      ["PBLOB","lpTotalNumberOfBytes","out"],
      ["PBLOB","lpTotalNumberOfFreeBytes","out"],
      ])

    dll.add_function( 'GetDiskFreeSpaceExW', 'BOOL',[
      ["PWCHAR","lpDirectoryName","in"],
      ["PBLOB","lpFreeBytesAvailableToCaller","out"],
      ["PBLOB","lpTotalNumberOfBytes","out"],
      ["PBLOB","lpTotalNumberOfFreeBytes","out"],
      ])

    dll.add_function( 'GetDiskFreeSpaceW', 'BOOL',[
      ["PWCHAR","lpRootPathName","in"],
      ["PDWORD","lpSectorsPerCluster","out"],
      ["PDWORD","lpBytesPerSector","out"],
      ["PDWORD","lpNumberOfFreeClusters","out"],
      ["PDWORD","lpTotalNumberOfClusters","out"],
      ])

    dll.add_function( 'GetDllDirectoryA', 'DWORD',[
      ["DWORD","nBufferLength","in"],
      ["PCHAR","lpBuffer","out"],
      ])

    dll.add_function( 'GetDllDirectoryW', 'DWORD',[
      ["DWORD","nBufferLength","in"],
      ["PWCHAR","lpBuffer","out"],
      ])

    dll.add_function( 'GetDriveTypeA', 'DWORD',[
      ["PCHAR","lpRootPathName","in"],
      ])

    dll.add_function( 'GetDriveTypeW', 'DWORD',[
      ["PWCHAR","lpRootPathName","in"],
      ])

    dll.add_function( 'GetEnvironmentStrings', 'LPVOID',[
      ])

    dll.add_function( 'GetEnvironmentStringsW', 'LPVOID',[
      ])

    dll.add_function( 'GetEnvironmentVariableA', 'DWORD',[
      ["PCHAR","lpName","in"],
      ["PCHAR","lpBuffer","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'GetEnvironmentVariableW', 'DWORD',[
      ["PWCHAR","lpName","in"],
      ["PWCHAR","lpBuffer","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'GetExitCodeProcess', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PDWORD","lpExitCode","out"],
      ])

    dll.add_function( 'GetExitCodeThread', 'BOOL',[
      ["HANDLE","hThread","in"],
      ["PDWORD","lpExitCode","out"],
      ])

    dll.add_function( 'GetFileAttributesA', 'DWORD',[
      ["PCHAR","lpFileName","in"],
      ])

    dll.add_function( 'GetFileAttributesExA', 'BOOL',[
      ["PCHAR","lpFileName","in"],
      ["PBLOB","fInfoLevelId","in"],
      ["PBLOB","lpFileInformation","out"],
      ])

    dll.add_function( 'GetFileAttributesExW', 'BOOL',[
      ["PWCHAR","lpFileName","in"],
      ["PBLOB","fInfoLevelId","in"],
      ["PBLOB","lpFileInformation","out"],
      ])

    dll.add_function( 'GetFileAttributesW', 'DWORD',[
      ["PWCHAR","lpFileName","in"],
      ])

    dll.add_function( 'GetFileInformationByHandle', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpFileInformation","out"],
      ])

    dll.add_function( 'GetFileSize', 'DWORD',[
      ["HANDLE","hFile","in"],
      ["PDWORD","lpFileSizeHigh","out"],
      ])

    dll.add_function( 'GetFileSizeEx', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpFileSize","out"],
      ])

    dll.add_function( 'GetFileTime', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpCreationTime","out"],
      ["PBLOB","lpLastAccessTime","out"],
      ["PBLOB","lpLastWriteTime","out"],
      ])

    dll.add_function( 'GetFileType', 'DWORD',[
      ["HANDLE","hFile","in"],
      ])

    dll.add_function( 'GetFirmwareEnvironmentVariableA', 'DWORD',[
      ["PCHAR","lpName","in"],
      ["PCHAR","lpGuid","in"],
      ["PBLOB","pBuffer","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'GetFirmwareEnvironmentVariableW', 'DWORD',[
      ["PWCHAR","lpName","in"],
      ["PWCHAR","lpGuid","in"],
      ["PBLOB","pBuffer","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'GetFullPathNameA', 'DWORD',[
      ["PCHAR","lpFileName","in"],
      ["DWORD","nBufferLength","in"],
      ["PCHAR","lpBuffer","out"],
      ["PBLOB","lpFilePart","out"],
      ])

    dll.add_function( 'GetFullPathNameW', 'DWORD',[
      ["PWCHAR","lpFileName","in"],
      ["DWORD","nBufferLength","in"],
      ["PWCHAR","lpBuffer","out"],
      ["PBLOB","lpFilePart","out"],
      ])

    dll.add_function( 'GetHandleInformation', 'BOOL',[
      ["HANDLE","hObject","in"],
      ["PDWORD","lpdwFlags","out"],
      ])

    dll.add_function( 'GetLargePageMinimum', 'DWORD',[
      ])

    dll.add_function( 'GetLastError', 'DWORD',[
      ])

    dll.add_function( 'GetLocalTime', 'VOID',[
      ["PBLOB","lpSystemTime","out"],
      ])

    dll.add_function( 'GetLogicalDriveStringsA', 'DWORD',[
      ["DWORD","nBufferLength","in"],
      ["PCHAR","lpBuffer","out"],
      ])

    dll.add_function( 'GetLogicalDriveStringsW', 'DWORD',[
      ["DWORD","nBufferLength","in"],
      ["PWCHAR","lpBuffer","out"],
      ])

    dll.add_function( 'GetLogicalDrives', 'DWORD',[
      ])

    dll.add_function( 'GetLogicalProcessorInformation', 'BOOL',[
      ["PBLOB","Buffer","out"],
      ["PDWORD","ReturnedLength","inout"],
      ])

    dll.add_function( 'GetLongPathNameA', 'DWORD',[
      ["PCHAR","lpszShortPath","in"],
      ["PCHAR","lpszLongPath","out"],
      ["DWORD","cchBuffer","in"],
      ])

    dll.add_function( 'GetLongPathNameW', 'DWORD',[
      ["PWCHAR","lpszShortPath","in"],
      ["PWCHAR","lpszLongPath","out"],
      ["DWORD","cchBuffer","in"],
      ])

    dll.add_function( 'GetMailslotInfo', 'BOOL',[
      ["HANDLE","hMailslot","in"],
      ["PDWORD","lpMaxMessageSize","out"],
      ["PDWORD","lpNextSize","out"],
      ["PDWORD","lpMessageCount","out"],
      ["PDWORD","lpReadTimeout","out"],
      ])

    dll.add_function( 'GetModuleFileNameA', 'DWORD',[
      ["HANDLE","hModule","in"],
      ["PBLOB","lpFilename","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'GetModuleFileNameW', 'DWORD',[
      ["HANDLE","hModule","in"],
      ["PBLOB","lpFilename","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'GetModuleHandleA', 'DWORD',[
      ["PCHAR","lpModuleName","in"],
      ])

    dll.add_function( 'GetModuleHandleExA', 'BOOL',[
      ["DWORD","dwFlags","in"],
      ["PCHAR","lpModuleName","in"],
      ["PDWORD","phModule","out"],
      ])

    dll.add_function( 'GetModuleHandleExW', 'BOOL',[
      ["DWORD","dwFlags","in"],
      ["PWCHAR","lpModuleName","in"],
      ["PDWORD","phModule","out"],
      ])

    dll.add_function( 'GetModuleHandleW', 'DWORD',[
      ["PWCHAR","lpModuleName","in"],
      ])

    dll.add_function( 'GetNamedPipeHandleStateA', 'BOOL',[
      ["HANDLE","hNamedPipe","in"],
      ["PDWORD","lpState","out"],
      ["PDWORD","lpCurInstances","out"],
      ["PDWORD","lpMaxCollectionCount","out"],
      ["PDWORD","lpCollectDataTimeout","out"],
      ["PCHAR","lpUserName","out"],
      ["DWORD","nMaxUserNameSize","in"],
      ])

    dll.add_function( 'GetNamedPipeHandleStateW', 'BOOL',[
      ["HANDLE","hNamedPipe","in"],
      ["PDWORD","lpState","out"],
      ["PDWORD","lpCurInstances","out"],
      ["PDWORD","lpMaxCollectionCount","out"],
      ["PDWORD","lpCollectDataTimeout","out"],
      ["PWCHAR","lpUserName","out"],
      ["DWORD","nMaxUserNameSize","in"],
      ])

    dll.add_function( 'GetNamedPipeInfo', 'BOOL',[
      ["HANDLE","hNamedPipe","in"],
      ["PDWORD","lpFlags","out"],
      ["PDWORD","lpOutBufferSize","out"],
      ["PDWORD","lpInBufferSize","out"],
      ["PDWORD","lpMaxInstances","out"],
      ])

    dll.add_function( 'GetNativeSystemInfo', 'VOID',[
      ["PBLOB","lpSystemInfo","out"],
      ])

    dll.add_function( 'GetNumaAvailableMemoryNode', 'BOOL',[
      ["BYTE","Node","in"],
      ["PBLOB","AvailableBytes","out"],
      ])

    dll.add_function( 'GetNumaHighestNodeNumber', 'BOOL',[
      ["PDWORD","HighestNodeNumber","out"],
      ])

    dll.add_function( 'GetNumaNodeProcessorMask', 'BOOL',[
      ["BYTE","Node","in"],
      ["PBLOB","ProcessorMask","out"],
      ])

    dll.add_function( 'GetNumaProcessorNode', 'BOOL',[
      ["BYTE","Processor","in"],
      ["PBLOB","NodeNumber","out"],
      ])

    dll.add_function( 'GetOverlappedResult', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpOverlapped","in"],
      ["PDWORD","lpNumberOfBytesTransferred","out"],
      ["BOOL","bWait","in"],
      ])

    dll.add_function( 'GetPriorityClass', 'DWORD',[
      ["HANDLE","hProcess","in"],
      ])

    dll.add_function( 'GetPrivateProfileIntA', 'DWORD',[
      ["PCHAR","lpAppName","in"],
      ["PCHAR","lpKeyName","in"],
      ["DWORD","nDefault","in"],
      ["PCHAR","lpFileName","in"],
      ])

    dll.add_function( 'GetPrivateProfileIntW', 'DWORD',[
      ["PWCHAR","lpAppName","in"],
      ["PWCHAR","lpKeyName","in"],
      ["DWORD","nDefault","in"],
      ["PWCHAR","lpFileName","in"],
      ])

    dll.add_function( 'GetPrivateProfileSectionA', 'DWORD',[
      ["PCHAR","lpAppName","in"],
      ["PCHAR","lpReturnedString","out"],
      ["DWORD","nSize","in"],
      ["PCHAR","lpFileName","in"],
      ])

    dll.add_function( 'GetPrivateProfileSectionNamesA', 'DWORD',[
      ["PCHAR","lpszReturnBuffer","out"],
      ["DWORD","nSize","in"],
      ["PCHAR","lpFileName","in"],
      ])

    dll.add_function( 'GetPrivateProfileSectionNamesW', 'DWORD',[
      ["PWCHAR","lpszReturnBuffer","out"],
      ["DWORD","nSize","in"],
      ["PWCHAR","lpFileName","in"],
      ])

    dll.add_function( 'GetPrivateProfileSectionW', 'DWORD',[
      ["PWCHAR","lpAppName","in"],
      ["PWCHAR","lpReturnedString","out"],
      ["DWORD","nSize","in"],
      ["PWCHAR","lpFileName","in"],
      ])

    dll.add_function( 'GetPrivateProfileStringA', 'DWORD',[
      ["PCHAR","lpAppName","in"],
      ["PCHAR","lpKeyName","in"],
      ["PCHAR","lpDefault","in"],
      ["PCHAR","lpReturnedString","out"],
      ["DWORD","nSize","in"],
      ["PCHAR","lpFileName","in"],
      ])

    dll.add_function( 'GetPrivateProfileStringW', 'DWORD',[
      ["PWCHAR","lpAppName","in"],
      ["PWCHAR","lpKeyName","in"],
      ["PWCHAR","lpDefault","in"],
      ["PWCHAR","lpReturnedString","out"],
      ["DWORD","nSize","in"],
      ["PWCHAR","lpFileName","in"],
      ])

    dll.add_function( 'GetPrivateProfileStructA', 'BOOL',[
      ["PCHAR","lpszSection","in"],
      ["PCHAR","lpszKey","in"],
      ["PBLOB","lpStruct","out"],
      ["DWORD","uSizeStruct","in"],
      ["PCHAR","szFile","in"],
      ])

    dll.add_function( 'GetPrivateProfileStructW', 'BOOL',[
      ["PWCHAR","lpszSection","in"],
      ["PWCHAR","lpszKey","in"],
      ["PBLOB","lpStruct","out"],
      ["DWORD","uSizeStruct","in"],
      ["PWCHAR","szFile","in"],
      ])

    dll.add_function( 'GetProcAddress', 'LPVOID',[
      ["HANDLE","hModule","in"],
      ["PCHAR","lpProcName","in"],
      ])

    dll.add_function( 'GetProcessAffinityMask', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PBLOB","lpProcessAffinityMask","out"],
      ["PBLOB","lpSystemAffinityMask","out"],
      ])

    dll.add_function( 'GetProcessHandleCount', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PDWORD","pdwHandleCount","out"],
      ])

    dll.add_function( 'GetProcessHeap', 'DWORD',[
      ])

    dll.add_function( 'GetProcessHeaps', 'DWORD',[
      ["DWORD","NumberOfHeaps","in"],
      ["PBLOB","ProcessHeaps","out"],
      ])

    dll.add_function( 'GetProcessId', 'DWORD',[
      ["DWORD","Process","in"],
      ])

    dll.add_function( 'GetProcessIdOfThread', 'DWORD',[
      ["DWORD","Thread","in"],
      ])

    dll.add_function( 'GetProcessIoCounters', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PBLOB","lpIoCounters","out"],
      ])

    dll.add_function( 'GetProcessPriorityBoost', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PBLOB","pDisablePriorityBoost","out"],
      ])

    dll.add_function( 'GetProcessShutdownParameters', 'BOOL',[
      ["PDWORD","lpdwLevel","out"],
      ["PDWORD","lpdwFlags","out"],
      ])

    dll.add_function( 'GetProcessTimes', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PBLOB","lpCreationTime","out"],
      ["PBLOB","lpExitTime","out"],
      ["PBLOB","lpKernelTime","out"],
      ["PBLOB","lpUserTime","out"],
      ])

    dll.add_function( 'GetProcessVersion', 'DWORD',[
      ["DWORD","ProcessId","in"],
      ])

    dll.add_function( 'GetProcessWorkingSetSize', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PDWORD","lpMinimumWorkingSetSize","out"],
      ["PDWORD","lpMaximumWorkingSetSize","out"],
      ])

    dll.add_function( 'GetProcessWorkingSetSizeEx', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PDWORD","lpMinimumWorkingSetSize","out"],
      ["PDWORD","lpMaximumWorkingSetSize","out"],
      ["PDWORD","Flags","out"],
      ])

    dll.add_function( 'GetProfileIntA', 'DWORD',[
      ["PCHAR","lpAppName","in"],
      ["PCHAR","lpKeyName","in"],
      ["DWORD","nDefault","in"],
      ])

    dll.add_function( 'GetProfileIntW', 'DWORD',[
      ["PWCHAR","lpAppName","in"],
      ["PWCHAR","lpKeyName","in"],
      ["DWORD","nDefault","in"],
      ])

    dll.add_function( 'GetProfileSectionA', 'DWORD',[
      ["PCHAR","lpAppName","in"],
      ["PCHAR","lpReturnedString","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'GetProfileSectionW', 'DWORD',[
      ["PWCHAR","lpAppName","in"],
      ["PWCHAR","lpReturnedString","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'GetProfileStringA', 'DWORD',[
      ["PCHAR","lpAppName","in"],
      ["PCHAR","lpKeyName","in"],
      ["PCHAR","lpDefault","in"],
      ["PCHAR","lpReturnedString","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'GetProfileStringW', 'DWORD',[
      ["PWCHAR","lpAppName","in"],
      ["PWCHAR","lpKeyName","in"],
      ["PWCHAR","lpDefault","in"],
      ["PWCHAR","lpReturnedString","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'GetQueuedCompletionStatus', 'BOOL',[
      ["DWORD","CompletionPort","in"],
      ["PDWORD","lpNumberOfBytesTransferred","out"],
      ["PBLOB","lpCompletionKey","out"],
      ["PBLOB","lpOverlapped","out"],
      ["DWORD","dwMilliseconds","in"],
      ])

    dll.add_function( 'GetShortPathNameA', 'DWORD',[
      ["PCHAR","lpszLongPath","in"],
      ["PCHAR","lpszShortPath","out"],
      ["DWORD","cchBuffer","in"],
      ])

    dll.add_function( 'GetShortPathNameW', 'DWORD',[
      ["PWCHAR","lpszLongPath","in"],
      ["PWCHAR","lpszShortPath","out"],
      ["DWORD","cchBuffer","in"],
      ])

    dll.add_function( 'GetStartupInfoA', 'VOID',[
      ["PBLOB","lpStartupInfo","out"],
      ])

    dll.add_function( 'GetStartupInfoW', 'VOID',[
      ["PBLOB","lpStartupInfo","out"],
      ])

    dll.add_function( 'GetStdHandle', 'DWORD',[
      ["DWORD","nStdHandle","in"],
      ])

    dll.add_function( 'GetSystemDirectoryA', 'DWORD',[
      ["PCHAR","lpBuffer","out"],
      ["DWORD","uSize","in"],
      ])

    dll.add_function( 'GetSystemDirectoryW', 'DWORD',[
      ["PWCHAR","lpBuffer","out"],
      ["DWORD","uSize","in"],
      ])

    dll.add_function( 'GetSystemFileCacheSize', 'BOOL',[
      ["PDWORD","lpMinimumFileCacheSize","out"],
      ["PDWORD","lpMaximumFileCacheSize","out"],
      ["PDWORD","lpFlags","out"],
      ])

    dll.add_function( 'GetSystemFirmwareTable', 'DWORD',[
      ["DWORD","FirmwareTableProviderSignature","in"],
      ["DWORD","FirmwareTableID","in"],
      ["PBLOB","pFirmwareTableBuffer","out"],
      ["DWORD","BufferSize","in"],
      ])

    dll.add_function( 'GetSystemInfo', 'VOID',[
      ["PBLOB","lpSystemInfo","out"],
      ])

    dll.add_function( 'GetSystemPowerStatus', 'BOOL',[
      ["PBLOB","lpSystemPowerStatus","out"],
      ])

    dll.add_function( 'GetSystemRegistryQuota', 'BOOL',[
      ["PDWORD","pdwQuotaAllowed","out"],
      ["PDWORD","pdwQuotaUsed","out"],
      ])

    dll.add_function( 'GetSystemTime', 'VOID',[
      ["PBLOB","lpSystemTime","out"],
      ])

    dll.add_function( 'GetSystemTimeAdjustment', 'BOOL',[
      ["PDWORD","lpTimeAdjustment","out"],
      ["PDWORD","lpTimeIncrement","out"],
      ["PBLOB","lpTimeAdjustmentDisabled","out"],
      ])

    dll.add_function( 'GetSystemTimeAsFileTime', 'VOID',[
      ["PBLOB","lpSystemTimeAsFileTime","out"],
      ])

    dll.add_function( 'GetSystemTimes', 'BOOL',[
      ["PBLOB","lpIdleTime","out"],
      ["PBLOB","lpKernelTime","out"],
      ["PBLOB","lpUserTime","out"],
      ])

    dll.add_function( 'GetSystemWindowsDirectoryA', 'DWORD',[
      ["PCHAR","lpBuffer","out"],
      ["DWORD","uSize","in"],
      ])

    dll.add_function( 'GetSystemWindowsDirectoryW', 'DWORD',[
      ["PWCHAR","lpBuffer","out"],
      ["DWORD","uSize","in"],
      ])

    dll.add_function( 'GetSystemWow64DirectoryA', 'DWORD',[
      ["PCHAR","lpBuffer","out"],
      ["DWORD","uSize","in"],
      ])

    dll.add_function( 'GetSystemWow64DirectoryW', 'DWORD',[
      ["PWCHAR","lpBuffer","out"],
      ["DWORD","uSize","in"],
      ])

    dll.add_function( 'GetTapeParameters', 'DWORD',[
      ["HANDLE","hDevice","in"],
      ["DWORD","dwOperation","in"],
      ["PDWORD","lpdwSize","inout"],
      ["PBLOB","lpTapeInformation","out"],
      ])

    dll.add_function( 'GetTapePosition', 'DWORD',[
      ["HANDLE","hDevice","in"],
      ["DWORD","dwPositionType","in"],
      ["PDWORD","lpdwPartition","out"],
      ["PDWORD","lpdwOffsetLow","out"],
      ["PDWORD","lpdwOffsetHigh","out"],
      ])

    dll.add_function( 'GetTapeStatus', 'DWORD',[
      ["HANDLE","hDevice","in"],
      ])

    dll.add_function( 'GetTempFileNameA', 'DWORD',[
      ["PCHAR","lpPathName","in"],
      ["PCHAR","lpPrefixString","in"],
      ["DWORD","uUnique","in"],
      ["PCHAR","lpTempFileName","out"],
      ])

    dll.add_function( 'GetTempFileNameW', 'DWORD',[
      ["PWCHAR","lpPathName","in"],
      ["PWCHAR","lpPrefixString","in"],
      ["DWORD","uUnique","in"],
      ["PWCHAR","lpTempFileName","out"],
      ])

    dll.add_function( 'GetTempPathA', 'DWORD',[
      ["DWORD","nBufferLength","in"],
      ["PCHAR","lpBuffer","out"],
      ])

    dll.add_function( 'GetTempPathW', 'DWORD',[
      ["DWORD","nBufferLength","in"],
      ["PWCHAR","lpBuffer","out"],
      ])

    dll.add_function( 'GetThreadContext', 'BOOL',[
      ["HANDLE","hThread","in"],
      ["PBLOB","lpContext","inout"],
      ])

    dll.add_function( 'GetThreadIOPendingFlag', 'BOOL',[
      ["HANDLE","hThread","in"],
      ["PBLOB","lpIOIsPending","out"],
      ])

    dll.add_function( 'GetThreadId', 'DWORD',[
      ["DWORD","Thread","in"],
      ])

    dll.add_function( 'GetThreadPriority', 'DWORD',[
      ["HANDLE","hThread","in"],
      ])

    dll.add_function( 'GetThreadPriorityBoost', 'BOOL',[
      ["HANDLE","hThread","in"],
      ["PBLOB","pDisablePriorityBoost","out"],
      ])

    dll.add_function( 'GetThreadSelectorEntry', 'BOOL',[
      ["HANDLE","hThread","in"],
      ["DWORD","dwSelector","in"],
      ["PBLOB","lpSelectorEntry","out"],
      ])

    dll.add_function( 'GetThreadTimes', 'BOOL',[
      ["HANDLE","hThread","in"],
      ["PBLOB","lpCreationTime","out"],
      ["PBLOB","lpExitTime","out"],
      ["PBLOB","lpKernelTime","out"],
      ["PBLOB","lpUserTime","out"],
      ])

    dll.add_function( 'GetTickCount', 'DWORD',[
      ])

    dll.add_function( 'GetTimeZoneInformation', 'DWORD',[
      ["PBLOB","lpTimeZoneInformation","out"],
      ])

    dll.add_function( 'GetVersion', 'DWORD',[
      ])

    dll.add_function( 'GetVersionExA', 'BOOL',[
      ["PBLOB","lpVersionInformation","inout"],
      ])

    dll.add_function( 'GetVersionExW', 'BOOL',[
      ["PBLOB","lpVersionInformation","inout"],
      ])

    dll.add_function( 'GetVolumeInformationA', 'BOOL',[
      ["PCHAR","lpRootPathName","in"],
      ["PCHAR","lpVolumeNameBuffer","out"],
      ["DWORD","nVolumeNameSize","in"],
      ["PDWORD","lpVolumeSerialNumber","out"],
      ["PDWORD","lpMaximumComponentLength","out"],
      ["PDWORD","lpFileSystemFlags","out"],
      ["PCHAR","lpFileSystemNameBuffer","out"],
      ["DWORD","nFileSystemNameSize","in"],
      ])

    dll.add_function( 'GetVolumeInformationW', 'BOOL',[
      ["PWCHAR","lpRootPathName","in"],
      ["PWCHAR","lpVolumeNameBuffer","out"],
      ["DWORD","nVolumeNameSize","in"],
      ["PDWORD","lpVolumeSerialNumber","out"],
      ["PDWORD","lpMaximumComponentLength","out"],
      ["PDWORD","lpFileSystemFlags","out"],
      ["PWCHAR","lpFileSystemNameBuffer","out"],
      ["DWORD","nFileSystemNameSize","in"],
      ])

    dll.add_function( 'GetVolumeNameForVolumeMountPointA', 'BOOL',[
      ["PCHAR","lpszVolumeMountPoint","in"],
      ["PCHAR","lpszVolumeName","out"],
      ["DWORD","cchBufferLength","in"],
      ])

    dll.add_function( 'GetVolumeNameForVolumeMountPointW', 'BOOL',[
      ["PWCHAR","lpszVolumeMountPoint","in"],
      ["PWCHAR","lpszVolumeName","out"],
      ["DWORD","cchBufferLength","in"],
      ])

    dll.add_function( 'GetVolumePathNameA', 'BOOL',[
      ["PCHAR","lpszFileName","in"],
      ["PCHAR","lpszVolumePathName","out"],
      ["DWORD","cchBufferLength","in"],
      ])

    dll.add_function( 'GetVolumePathNameW', 'BOOL',[
      ["PWCHAR","lpszFileName","in"],
      ["PWCHAR","lpszVolumePathName","out"],
      ["DWORD","cchBufferLength","in"],
      ])

    dll.add_function( 'GetVolumePathNamesForVolumeNameA', 'BOOL',[
      ["PCHAR","lpszVolumeName","in"],
      ["PBLOB","lpszVolumePathNames","out"],
      ["DWORD","cchBufferLength","in"],
      ["PDWORD","lpcchReturnLength","out"],
      ])

    dll.add_function( 'GetVolumePathNamesForVolumeNameW', 'BOOL',[
      ["PWCHAR","lpszVolumeName","in"],
      ["PBLOB","lpszVolumePathNames","out"],
      ["DWORD","cchBufferLength","in"],
      ["PDWORD","lpcchReturnLength","out"],
      ])

    dll.add_function( 'GetWindowsDirectoryA', 'DWORD',[
      ["PCHAR","lpBuffer","out"],
      ["DWORD","uSize","in"],
      ])

    dll.add_function( 'GetWindowsDirectoryW', 'DWORD',[
      ["PWCHAR","lpBuffer","out"],
      ["DWORD","uSize","in"],
      ])

    dll.add_function( 'GetWriteWatch', 'DWORD',[
      ["DWORD","dwFlags","in"],
      ["PBLOB","lpBaseAddress","in"],
      ["DWORD","dwRegionSize","in"],
      ["PBLOB","lpAddresses","out"],
      ["PBLOB","lpdwCount","inout"],
      ["PDWORD","lpdwGranularity","out"],
      ])

    dll.add_function( 'GlobalAddAtomA', 'WORD',[
      ["PCHAR","lpString","in"],
      ])

    dll.add_function( 'GlobalAddAtomW', 'WORD',[
      ["PWCHAR","lpString","in"],
      ])

    dll.add_function( 'GlobalAlloc', 'DWORD',[
      ["DWORD","uFlags","in"],
      ["DWORD","dwBytes","in"],
      ])

    dll.add_function( 'GlobalCompact', 'DWORD',[
      ["DWORD","dwMinFree","in"],
      ])

    dll.add_function( 'GlobalDeleteAtom', 'WORD',[
      ["WORD","nAtom","in"],
      ])

    dll.add_function( 'GlobalFindAtomA', 'WORD',[
      ["PCHAR","lpString","in"],
      ])

    dll.add_function( 'GlobalFindAtomW', 'WORD',[
      ["PWCHAR","lpString","in"],
      ])

    dll.add_function( 'GlobalFix', 'VOID',[
      ["HANDLE","hMem","in"],
      ])

    dll.add_function( 'GlobalFlags', 'DWORD',[
      ["HANDLE","hMem","in"],
      ])

    dll.add_function( 'GlobalFree', 'DWORD',[
      ["HANDLE","hMem","in"],
      ])

    dll.add_function( 'GlobalGetAtomNameA', 'DWORD',[
      ["WORD","nAtom","in"],
      ["PCHAR","lpBuffer","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'GlobalGetAtomNameW', 'DWORD',[
      ["WORD","nAtom","in"],
      ["PWCHAR","lpBuffer","out"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'GlobalHandle', 'DWORD',[
      ["PBLOB","pMem","in"],
      ])

    dll.add_function( 'GlobalLock', 'LPVOID',[
      ["HANDLE","hMem","in"],
      ])

    dll.add_function( 'GlobalMemoryStatus', 'VOID',[
      ["PBLOB","lpBuffer","out"],
      ])

    dll.add_function( 'GlobalMemoryStatusEx', 'BOOL',[
      ["PBLOB","lpBuffer","out"],
      ])

    dll.add_function( 'GlobalReAlloc', 'DWORD',[
      ["HANDLE","hMem","in"],
      ["DWORD","dwBytes","in"],
      ["DWORD","uFlags","in"],
      ])

    dll.add_function( 'GlobalSize', 'DWORD',[
      ["HANDLE","hMem","in"],
      ])

    dll.add_function( 'GlobalUnWire', 'BOOL',[
      ["HANDLE","hMem","in"],
      ])

    dll.add_function( 'GlobalUnfix', 'VOID',[
      ["HANDLE","hMem","in"],
      ])

    dll.add_function( 'GlobalUnlock', 'BOOL',[
      ["HANDLE","hMem","in"],
      ])

    dll.add_function( 'GlobalWire', 'LPVOID',[
      ["HANDLE","hMem","in"],
      ])

    dll.add_function( 'HeapAlloc', 'LPVOID',[
      ["HANDLE","hHeap","in"],
      ["DWORD","dwFlags","in"],
      ["DWORD","dwBytes","in"],
      ])

    dll.add_function( 'HeapCompact', 'DWORD',[
      ["HANDLE","hHeap","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function( 'HeapCreate', 'DWORD',[
      ["DWORD","flOptions","in"],
      ["DWORD","dwInitialSize","in"],
      ["DWORD","dwMaximumSize","in"],
      ])

    dll.add_function( 'HeapDestroy', 'BOOL',[
      ["HANDLE","hHeap","in"],
      ])

    dll.add_function( 'HeapFree', 'BOOL',[
      ["HANDLE","hHeap","inout"],
      ["DWORD","dwFlags","in"],
      ["LPVOID","lpMem","in"],
      ])

    dll.add_function( 'HeapLock', 'BOOL',[
      ["HANDLE","hHeap","in"],
      ])

    dll.add_function( 'HeapQueryInformation', 'BOOL',[
      ["HANDLE","heapHandle","in"],
      ["PDWORD","HeapInformationClass","in"],
      ["PBLOB","HeapInformation","out"],
      ["HANDLE","heapInformationLength","in"],
      ["PDWORD","ReturnLength","out"],
      ])

    dll.add_function( 'HeapReAlloc', 'LPVOID',[
      ["HANDLE","hHeap","inout"],
      ["DWORD","dwFlags","in"],
      ["LPVOID","lpMem","in"],
      ["DWORD","dwBytes","in"],
      ])

    dll.add_function( 'HeapSetInformation', 'BOOL',[
      ["HANDLE","heapHandle","in"],
      ["PDWORD","HeapInformationClass","in"],
      ["PBLOB","HeapInformation","in"],
      ["HANDLE","heapInformationLength","in"],
      ])

    dll.add_function( 'HeapSize', 'DWORD',[
      ["HANDLE","hHeap","in"],
      ["DWORD","dwFlags","in"],
      ["LPVOID","lpMem","in"],
      ])

    dll.add_function( 'HeapUnlock', 'BOOL',[
      ["HANDLE","hHeap","in"],
      ])

    dll.add_function( 'HeapValidate', 'BOOL',[
      ["HANDLE","hHeap","in"],
      ["DWORD","dwFlags","in"],
      ["LPVOID","lpMem","in"],
      ])

    dll.add_function( 'HeapWalk', 'BOOL',[
      ["HANDLE","hHeap","in"],
      ["PBLOB","lpEntry","inout"],
      ])

    dll.add_function( 'InitAtomTable', 'BOOL',[
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'InitializeCriticalSection', 'VOID',[
      ["PBLOB","lpCriticalSection","out"],
      ])

    dll.add_function( 'InitializeCriticalSectionAndSpinCount', 'BOOL',[
      ["PBLOB","lpCriticalSection","out"],
      ["DWORD","dwSpinCount","in"],
      ])

    dll.add_function( 'InitializeSListHead', 'VOID',[
      ["PBLOB","ListHead","inout"],
      ])

    dll.add_function( 'InterlockedCompareExchange', 'DWORD',[
      ["PDWORD","Destination","inout"],
      ["DWORD","ExChange","in"],
      ["DWORD","Comperand","in"],
      ])

    dll.add_function( 'InterlockedCompareExchange64', 'LPVOID',[
      ["PBLOB","Destination","inout"],
      ["PBLOB","ExChange","in"],
      ["PBLOB","Comperand","in"],
      ])

    dll.add_function( 'InterlockedDecrement', 'DWORD',[
      ["PDWORD","lpAddend","inout"],
      ])

    dll.add_function( 'InterlockedExchange', 'DWORD',[
      ["PDWORD","Target","inout"],
      ["DWORD","Value","in"],
      ])

    dll.add_function( 'InterlockedExchangeAdd', 'DWORD',[
      ["PDWORD","Addend","inout"],
      ["DWORD","Value","in"],
      ])

    dll.add_function( 'InterlockedFlushSList', 'LPVOID',[
      ["PBLOB","ListHead","inout"],
      ])

    dll.add_function( 'InterlockedIncrement', 'DWORD',[
      ["PDWORD","lpAddend","inout"],
      ])

    dll.add_function( 'InterlockedPopEntrySList', 'LPVOID',[
      ["PBLOB","ListHead","inout"],
      ])

    dll.add_function( 'InterlockedPushEntrySList', 'LPVOID',[
      ["PBLOB","ListHead","inout"],
      ["PBLOB","ListEntry","inout"],
      ])

    dll.add_function( 'IsBadCodePtr', 'BOOL',[
      ["PBLOB","lpfn","in"],
      ])

    dll.add_function( 'IsBadHugeReadPtr', 'BOOL',[
      ["DWORD","ucb","in"],
      ])

    dll.add_function( 'IsBadHugeWritePtr', 'BOOL',[
      ["PBLOB","lp","in"],
      ["DWORD","ucb","in"],
      ])

    dll.add_function( 'IsBadReadPtr', 'BOOL',[
      ["DWORD","ucb","in"],
      ])

    dll.add_function( 'IsBadStringPtrA', 'BOOL',[
      ["PCHAR","lpsz","in"],
      ["DWORD","ucchMax","in"],
      ])

    dll.add_function( 'IsBadStringPtrW', 'BOOL',[
      ["PWCHAR","lpsz","in"],
      ["DWORD","ucchMax","in"],
      ])

    dll.add_function( 'IsBadWritePtr', 'BOOL',[
      ["PBLOB","lp","in"],
      ["DWORD","ucb","in"],
      ])

    dll.add_function( 'IsDebuggerPresent', 'BOOL',[
      ])

    dll.add_function( 'IsProcessInJob', 'BOOL',[
      ["DWORD","ProcessHandle","in"],
      ["DWORD","JobHandle","in"],
      ["PBLOB","Result","out"],
      ])

    dll.add_function( 'IsProcessorFeaturePresent', 'BOOL',[
      ["DWORD","ProcessorFeature","in"],
      ])

    dll.add_function( 'IsSystemResumeAutomatic', 'BOOL',[
      ])

    dll.add_function( 'IsWow64Process', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PBLOB","Wow64Process","out"],
      ])

    dll.add_function( 'LeaveCriticalSection', 'VOID',[
      ["PBLOB","lpCriticalSection","inout"],
      ])

    dll.add_function( 'LoadLibraryA', 'DWORD',[
      ["PCHAR","lpLibFileName","in"],
      ])

    dll.add_function( 'LoadLibraryExA', 'DWORD',[
      ["PCHAR","lpLibFileName","in"],
      ["HANDLE","hFile","inout"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function( 'LoadLibraryExW', 'DWORD',[
      ["PWCHAR","lpLibFileName","in"],
      ["HANDLE","hFile","inout"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function( 'LoadLibraryW', 'DWORD',[
      ["PWCHAR","lpLibFileName","in"],
      ])

    dll.add_function( 'LoadModule', 'DWORD',[
      ["PCHAR","lpModuleName","in"],
      ["PBLOB","lpParameterBlock","in"],
      ])

    dll.add_function( 'LoadResource', 'DWORD',[
      ["HANDLE","hModule","in"],
      ["HANDLE","hResInfo","in"],
      ])

    dll.add_function( 'LocalAlloc', 'DWORD',[
      ["DWORD","uFlags","in"],
      ["DWORD","uBytes","in"],
      ])

    dll.add_function( 'LocalCompact', 'DWORD',[
      ["DWORD","uMinFree","in"],
      ])

    dll.add_function( 'LocalFileTimeToFileTime', 'BOOL',[
      ["PBLOB","lpLocalFileTime","in"],
      ["PBLOB","lpFileTime","out"],
      ])

    dll.add_function( 'LocalFlags', 'DWORD',[
      ["HANDLE","hMem","in"],
      ])

    dll.add_function( 'LocalFree', 'DWORD',[
      ["HANDLE","hMem","in"],
      ])

    dll.add_function( 'LocalHandle', 'DWORD',[
      ["PBLOB","pMem","in"],
      ])

    dll.add_function( 'LocalLock', 'LPVOID',[
      ["HANDLE","hMem","in"],
      ])

    dll.add_function( 'LocalReAlloc', 'DWORD',[
      ["HANDLE","hMem","in"],
      ["DWORD","uBytes","in"],
      ["DWORD","uFlags","in"],
      ])

    dll.add_function( 'LocalShrink', 'DWORD',[
      ["HANDLE","hMem","in"],
      ["DWORD","cbNewSize","in"],
      ])

    dll.add_function( 'LocalSize', 'DWORD',[
      ["HANDLE","hMem","in"],
      ])

    dll.add_function( 'LocalUnlock', 'BOOL',[
      ["HANDLE","hMem","in"],
      ])

    dll.add_function( 'LockFile', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["DWORD","dwFileOffsetLow","in"],
      ["DWORD","dwFileOffsetHigh","in"],
      ["DWORD","nNumberOfBytesToLockLow","in"],
      ["DWORD","nNumberOfBytesToLockHigh","in"],
      ])

    dll.add_function( 'LockFileEx', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["DWORD","dwFlags","in"],
      ["DWORD","dwReserved","inout"],
      ["DWORD","nNumberOfBytesToLockLow","in"],
      ["DWORD","nNumberOfBytesToLockHigh","in"],
      ["PBLOB","lpOverlapped","inout"],
      ])

    dll.add_function( 'LockResource', 'LPVOID',[
      ["HANDLE","hResData","in"],
      ])

    dll.add_function( 'MapUserPhysicalPages', 'BOOL',[
      ["PBLOB","VirtualAddress","in"],
      ["PDWORD","NumberOfPages","in"],
      ["PBLOB","PageArray","in"],
      ])

    dll.add_function( 'MapUserPhysicalPagesScatter', 'BOOL',[
      ["PBLOB","VirtualAddresses","in"],
      ["PDWORD","NumberOfPages","in"],
      ["PBLOB","PageArray","in"],
      ])

    dll.add_function( 'MapViewOfFile', 'LPVOID',[
      ["HANDLE","hFileMappingObject","in"],
      ["DWORD","dwDesiredAccess","in"],
      ["DWORD","dwFileOffsetHigh","in"],
      ["DWORD","dwFileOffsetLow","in"],
      ["DWORD","dwNumberOfBytesToMap","in"],
      ])

    dll.add_function( 'MapViewOfFileEx', 'LPVOID',[
      ["HANDLE","hFileMappingObject","in"],
      ["DWORD","dwDesiredAccess","in"],
      ["DWORD","dwFileOffsetHigh","in"],
      ["DWORD","dwFileOffsetLow","in"],
      ["DWORD","dwNumberOfBytesToMap","in"],
      ["PBLOB","lpBaseAddress","in"],
      ])

    dll.add_function( 'MoveFileA', 'BOOL',[
      ["PCHAR","lpExistingFileName","in"],
      ["PCHAR","lpNewFileName","in"],
      ])

    dll.add_function( 'MoveFileExA', 'BOOL',[
      ["PCHAR","lpExistingFileName","in"],
      ["PCHAR","lpNewFileName","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function( 'MoveFileExW', 'BOOL',[
      ["PWCHAR","lpExistingFileName","in"],
      ["PWCHAR","lpNewFileName","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function( 'MoveFileW', 'BOOL',[
      ["PWCHAR","lpExistingFileName","in"],
      ["PWCHAR","lpNewFileName","in"],
      ])

    dll.add_function( 'MoveFileWithProgressA', 'BOOL',[
      ["PCHAR","lpExistingFileName","in"],
      ["PCHAR","lpNewFileName","in"],
      ["PBLOB","lpProgressRoutine","in"],
      ["PBLOB","lpData","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function( 'MoveFileWithProgressW', 'BOOL',[
      ["PWCHAR","lpExistingFileName","in"],
      ["PWCHAR","lpNewFileName","in"],
      ["PBLOB","lpProgressRoutine","in"],
      ["PBLOB","lpData","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function( 'MulDiv', 'DWORD',[
      ["DWORD","nNumber","in"],
      ["DWORD","nNumerator","in"],
      ["DWORD","nDenominator","in"],
      ])

    dll.add_function( 'NeedCurrentDirectoryForExePathA', 'BOOL',[
      ["PCHAR","ExeName","in"],
      ])

    dll.add_function( 'NeedCurrentDirectoryForExePathW', 'BOOL',[
      ["PWCHAR","ExeName","in"],
      ])

    dll.add_function( 'OpenEventA', 'DWORD',[
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["PCHAR","lpName","in"],
      ])

    dll.add_function( 'OpenEventW', 'DWORD',[
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["PWCHAR","lpName","in"],
      ])

    dll.add_function( 'OpenFile', 'DWORD',[
      ["PCHAR","lpFileName","in"],
      ["PBLOB","lpReOpenBuff","inout"],
      ["DWORD","uStyle","in"],
      ])

    dll.add_function( 'OpenFileMappingA', 'DWORD',[
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["PCHAR","lpName","in"],
      ])

    dll.add_function( 'OpenFileMappingW', 'DWORD',[
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["PWCHAR","lpName","in"],
      ])

    dll.add_function( 'OpenJobObjectA', 'DWORD',[
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["PCHAR","lpName","in"],
      ])

    dll.add_function( 'OpenJobObjectW', 'DWORD',[
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["PWCHAR","lpName","in"],
      ])

    dll.add_function( 'OpenMutexA', 'DWORD',[
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["PCHAR","lpName","in"],
      ])

    dll.add_function( 'OpenMutexW', 'DWORD',[
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["PWCHAR","lpName","in"],
      ])

    dll.add_function( 'OpenProcess', 'DWORD',[
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["DWORD","dwProcessId","in"],
      ])

    dll.add_function( 'OpenSemaphoreA', 'DWORD',[
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["PCHAR","lpName","in"],
      ])

    dll.add_function( 'OpenSemaphoreW', 'DWORD',[
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["PWCHAR","lpName","in"],
      ])

    dll.add_function( 'OpenThread', 'DWORD',[
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["DWORD","dwThreadId","in"],
      ])

    dll.add_function( 'OpenWaitableTimerA', 'DWORD',[
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["PCHAR","lpTimerName","in"],
      ])

    dll.add_function( 'OpenWaitableTimerW', 'DWORD',[
      ["DWORD","dwDesiredAccess","in"],
      ["BOOL","bInheritHandle","in"],
      ["PWCHAR","lpTimerName","in"],
      ])

    dll.add_function( 'OutputDebugStringA', 'VOID',[
      ["PCHAR","lpOutputString","in"],
      ])

    dll.add_function( 'OutputDebugStringW', 'VOID',[
      ["PWCHAR","lpOutputString","in"],
      ])

    dll.add_function( 'PeekNamedPipe', 'BOOL',[
      ["HANDLE","hNamedPipe","in"],
      ["PBLOB","lpBuffer","out"],
      ["DWORD","nBufferSize","in"],
      ["PDWORD","lpBytesRead","out"],
      ["PDWORD","lpTotalBytesAvail","out"],
      ["PDWORD","lpBytesLeftThisMessage","out"],
      ])

    dll.add_function( 'PostQueuedCompletionStatus', 'BOOL',[
      ["DWORD","CompletionPort","in"],
      ["DWORD","dwNumberOfBytesTransferred","in"],
      ["PDWORD","dwCompletionKey","in"],
      ["PBLOB","lpOverlapped","in"],
      ])

    dll.add_function( 'PrepareTape', 'DWORD',[
      ["HANDLE","hDevice","in"],
      ["DWORD","dwOperation","in"],
      ["BOOL","bImmediate","in"],
      ])

    dll.add_function( 'ProcessIdToSessionId', 'BOOL',[
      ["DWORD","dwProcessId","in"],
      ["PDWORD","pSessionId","out"],
      ])

    dll.add_function( 'PulseEvent', 'BOOL',[
      ["HANDLE","hEvent","in"],
      ])

    dll.add_function( 'PurgeComm', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function( 'QueryActCtxW', 'BOOL',[
      ["DWORD","dwFlags","in"],
      ["HANDLE","hActCtx","in"],
      ["PBLOB","pvSubInstance","in"],
      ["DWORD","ulInfoClass","in"],
      ["PBLOB","pvBuffer","out"],
      ["DWORD","cbBuffer","in"],
      ["PDWORD","pcbWrittenOrRequired","out"],
      ])

    dll.add_function( 'QueryDepthSList', 'WORD',[
      ["PBLOB","ListHead","in"],
      ])

    dll.add_function( 'QueryDosDeviceA', 'DWORD',[
      ["PCHAR","lpDeviceName","in"],
      ["PCHAR","lpTargetPath","out"],
      ["DWORD","ucchMax","in"],
      ])

    dll.add_function( 'QueryDosDeviceW', 'DWORD',[
      ["PWCHAR","lpDeviceName","in"],
      ["PWCHAR","lpTargetPath","out"],
      ["DWORD","ucchMax","in"],
      ])

    dll.add_function( 'QueryInformationJobObject', 'BOOL',[
      ["HANDLE","hJob","in"],
      ["PBLOB","JobObjectInformationClass","in"],
      ["PBLOB","lpJobObjectInformation","out"],
      ["DWORD","cbJobObjectInformationLength","in"],
      ["PDWORD","lpReturnLength","out"],
      ])

    dll.add_function( 'QueryMemoryResourceNotification', 'BOOL',[
      ["DWORD","ResourceNotificationHandle","in"],
      ["PBLOB","ResourceState","out"],
      ])

    dll.add_function( 'QueryPerformanceCounter', 'BOOL',[
      ["PBLOB","lpPerformanceCount","out"],
      ])

    dll.add_function( 'QueryPerformanceFrequency', 'BOOL',[
      ["PBLOB","lpFrequency","out"],
      ])

    dll.add_function( 'QueueUserAPC', 'DWORD',[
      ["PBLOB","pfnAPC","in"],
      ["HANDLE","hThread","in"],
      ["PDWORD","dwData","in"],
      ])

    dll.add_function( 'QueueUserWorkItem', 'BOOL',[
      ["PBLOB","Function","in"],
      ["PBLOB","Context","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function( 'RaiseException', 'VOID',[
      ["DWORD","dwExceptionCode","in"],
      ["DWORD","dwExceptionFlags","in"],
      ["DWORD","nNumberOfArguments","in"],
      ["PBLOB","lpArguments","in"],
      ])

    dll.add_function( 'ReOpenFile', 'DWORD',[
      ["HANDLE","hOriginalFile","in"],
      ["DWORD","dwDesiredAccess","in"],
      ["DWORD","dwShareMode","in"],
      ["DWORD","dwFlagsAndAttributes","in"],
      ])

    dll.add_function( 'ReadDirectoryChangesW', 'BOOL',[
      ["HANDLE","hDirectory","in"],
      ["PBLOB","lpBuffer","out"],
      ["DWORD","nBufferLength","in"],
      ["BOOL","bWatchSubtree","in"],
      ["DWORD","dwNotifyFilter","in"],
      ["PDWORD","lpBytesReturned","out"],
      ["PBLOB","lpOverlapped","inout"],
      ["PBLOB","lpCompletionRoutine","in"],
      ])

    dll.add_function( 'ReadFile', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpBuffer","out"],
      ["DWORD","nNumberOfBytesToRead","in"],
      ["PDWORD","lpNumberOfBytesRead","out"],
      ["PBLOB","lpOverlapped","inout"],
      ])

    dll.add_function( 'ReadFileEx', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpBuffer","out"],
      ["DWORD","nNumberOfBytesToRead","in"],
      ["PBLOB","lpOverlapped","inout"],
      ["PBLOB","lpCompletionRoutine","in"],
      ])

    dll.add_function( 'ReadFileScatter', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","aSegmentArray[]","in"],
      ["DWORD","nNumberOfBytesToRead","in"],
      ["PDWORD","lpReserved","inout"],
      ["PBLOB","lpOverlapped","inout"],
      ])

    dll.add_function( 'ReadProcessMemory', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PBLOB","lpBaseAddress","in"],
      ["PBLOB","lpBuffer","out"],
      ["DWORD","nSize","in"],
      ["PDWORD","lpNumberOfBytesRead","out"],
      ])

    dll.add_function( 'RegisterWaitForSingleObject', 'BOOL',[
      ["PDWORD","phNewWaitObject","out"],
      ["HANDLE","hObject","in"],
      ["PBLOB","Callback","in"],
      ["PBLOB","Context","in"],
      ["DWORD","dwMilliseconds","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function( 'RegisterWaitForSingleObjectEx', 'DWORD',[
      ["HANDLE","hObject","in"],
      ["PBLOB","Callback","in"],
      ["PBLOB","Context","in"],
      ["DWORD","dwMilliseconds","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function( 'ReleaseActCtx', 'VOID',[
      ["HANDLE","hActCtx","inout"],
      ])

    dll.add_function( 'ReleaseMutex', 'BOOL',[
      ["HANDLE","hMutex","in"],
      ])

    dll.add_function( 'ReleaseSemaphore', 'BOOL',[
      ["HANDLE","hSemaphore","in"],
      ["DWORD","lReleaseCount","in"],
      ["PBLOB","lpPreviousCount","out"],
      ])

    dll.add_function( 'RemoveDirectoryA', 'BOOL',[
      ["PCHAR","lpPathName","in"],
      ])

    dll.add_function( 'RemoveDirectoryW', 'BOOL',[
      ["PWCHAR","lpPathName","in"],
      ])

    dll.add_function( 'RemoveVectoredContinueHandler', 'DWORD',[
      ["PBLOB","Handle","in"],
      ])

    dll.add_function( 'RemoveVectoredExceptionHandler', 'DWORD',[
      ["PBLOB","Handle","in"],
      ])

    dll.add_function( 'ReplaceFileA', 'BOOL',[
      ["PCHAR","lpReplacedFileName","in"],
      ["PCHAR","lpReplacementFileName","in"],
      ["PCHAR","lpBackupFileName","in"],
      ["DWORD","dwReplaceFlags","in"],
      ["PBLOB","lpExclude","inout"],
      ["PBLOB","lpReserved","inout"],
      ])

    dll.add_function( 'ReplaceFileW', 'BOOL',[
      ["PWCHAR","lpReplacedFileName","in"],
      ["PWCHAR","lpReplacementFileName","in"],
      ["PWCHAR","lpBackupFileName","in"],
      ["DWORD","dwReplaceFlags","in"],
      ["PBLOB","lpExclude","inout"],
      ["PBLOB","lpReserved","inout"],
      ])

    dll.add_function( 'RequestDeviceWakeup', 'BOOL',[
      ["HANDLE","hDevice","in"],
      ])

    dll.add_function( 'RequestWakeupLatency', 'BOOL',[
      ["PBLOB","latency","in"],
      ])

    dll.add_function( 'ResetEvent', 'BOOL',[
      ["HANDLE","hEvent","in"],
      ])

    dll.add_function( 'ResetWriteWatch', 'DWORD',[
      ["PBLOB","lpBaseAddress","in"],
      ["DWORD","dwRegionSize","in"],
      ])

    dll.add_function( 'RestoreLastError', 'VOID',[
      ["DWORD","dwErrCode","in"],
      ])

    dll.add_function( 'ResumeThread', 'DWORD',[
      ["HANDLE","hThread","in"],
      ])

    dll.add_function( 'SearchPathA', 'DWORD',[
      ["PCHAR","lpPath","in"],
      ["PCHAR","lpFileName","in"],
      ["PCHAR","lpExtension","in"],
      ["DWORD","nBufferLength","in"],
      ["PCHAR","lpBuffer","out"],
      ["PBLOB","lpFilePart","out"],
      ])

    dll.add_function( 'SearchPathW', 'DWORD',[
      ["PWCHAR","lpPath","in"],
      ["PWCHAR","lpFileName","in"],
      ["PWCHAR","lpExtension","in"],
      ["DWORD","nBufferLength","in"],
      ["PWCHAR","lpBuffer","out"],
      ["PBLOB","lpFilePart","out"],
      ])

    dll.add_function( 'SetCommBreak', 'BOOL',[
      ["HANDLE","hFile","in"],
      ])

    dll.add_function( 'SetCommConfig', 'BOOL',[
      ["HANDLE","hCommDev","in"],
      ["PBLOB","lpCC","in"],
      ["DWORD","dwSize","in"],
      ])

    dll.add_function( 'SetCommMask', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["DWORD","dwEvtMask","in"],
      ])

    dll.add_function( 'SetCommState', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpDCB","in"],
      ])

    dll.add_function( 'SetCommTimeouts', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpCommTimeouts","in"],
      ])

    dll.add_function( 'SetComputerNameA', 'BOOL',[
      ["PCHAR","lpComputerName","in"],
      ])

    dll.add_function( 'SetComputerNameExA', 'BOOL',[
      ["DWORD","NameType","in"],
      ["PCHAR","lpBuffer","in"],
      ])

    dll.add_function( 'SetComputerNameExW', 'BOOL',[
      ["DWORD","NameType","in"],
      ["PWCHAR","lpBuffer","in"],
      ])

    dll.add_function( 'SetComputerNameW', 'BOOL',[
      ["PWCHAR","lpComputerName","in"],
      ])

    dll.add_function( 'SetCriticalSectionSpinCount', 'DWORD',[
      ["PBLOB","lpCriticalSection","inout"],
      ["DWORD","dwSpinCount","in"],
      ])

    dll.add_function( 'SetCurrentDirectoryA', 'BOOL',[
      ["PCHAR","lpPathName","in"],
      ])

    dll.add_function( 'SetCurrentDirectoryW', 'BOOL',[
      ["PWCHAR","lpPathName","in"],
      ])

    dll.add_function( 'SetDefaultCommConfigA', 'BOOL',[
      ["PCHAR","lpszName","in"],
      ["PBLOB","lpCC","in"],
      ["DWORD","dwSize","in"],
      ])

    dll.add_function( 'SetDefaultCommConfigW', 'BOOL',[
      ["PWCHAR","lpszName","in"],
      ["PBLOB","lpCC","in"],
      ["DWORD","dwSize","in"],
      ])

    dll.add_function( 'SetDllDirectoryA', 'BOOL',[
      ["PCHAR","lpPathName","in"],
      ])

    dll.add_function( 'SetDllDirectoryW', 'BOOL',[
      ["PWCHAR","lpPathName","in"],
      ])

    dll.add_function( 'SetEndOfFile', 'BOOL',[
      ["HANDLE","hFile","in"],
      ])

    dll.add_function( 'SetEnvironmentStringsA', 'BOOL',[
      ["PBLOB","NewEnvironment","in"],
      ])

    dll.add_function( 'SetEnvironmentStringsW', 'BOOL',[
      ["PBLOB","NewEnvironment","in"],
      ])

    dll.add_function( 'SetEnvironmentVariableA', 'BOOL',[
      ["PCHAR","lpName","in"],
      ["PCHAR","lpValue","in"],
      ])

    dll.add_function( 'SetEnvironmentVariableW', 'BOOL',[
      ["PWCHAR","lpName","in"],
      ["PWCHAR","lpValue","in"],
      ])

    dll.add_function( 'SetErrorMode', 'DWORD',[
      ["DWORD","uMode","in"],
      ])

    dll.add_function( 'SetEvent', 'BOOL',[
      ["HANDLE","hEvent","in"],
      ])

    dll.add_function( 'SetFileApisToANSI', 'VOID',[
      ])

    dll.add_function( 'SetFileApisToOEM', 'VOID',[
      ])

    dll.add_function( 'SetFileAttributesA', 'BOOL',[
      ["PCHAR","lpFileName","in"],
      ["DWORD","dwFileAttributes","in"],
      ])

    dll.add_function( 'SetFileAttributesW', 'BOOL',[
      ["PWCHAR","lpFileName","in"],
      ["DWORD","dwFileAttributes","in"],
      ])

    dll.add_function( 'SetFilePointer', 'DWORD',[
      ["HANDLE","hFile","in"],
      ["DWORD","lDistanceToMove","in"],
      ["PDWORD","lpDistanceToMoveHigh","in"],
      ["DWORD","dwMoveMethod","in"],
      ])

    dll.add_function( 'SetFilePointerEx', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","liDistanceToMove","in"],
      ["PBLOB","lpNewFilePointer","out"],
      ["DWORD","dwMoveMethod","in"],
      ])

    dll.add_function( 'SetFileShortNameA', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PCHAR","lpShortName","in"],
      ])

    dll.add_function( 'SetFileShortNameW', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PWCHAR","lpShortName","in"],
      ])

    dll.add_function( 'SetFileTime', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpCreationTime","in"],
      ["PBLOB","lpLastAccessTime","in"],
      ["PBLOB","lpLastWriteTime","in"],
      ])

    dll.add_function( 'SetFileValidData', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","ValidDataLength","in"],
      ])

    dll.add_function( 'SetFirmwareEnvironmentVariableA', 'BOOL',[
      ["PCHAR","lpName","in"],
      ["PCHAR","lpGuid","in"],
      ["PBLOB","pValue","in"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'SetFirmwareEnvironmentVariableW', 'BOOL',[
      ["PWCHAR","lpName","in"],
      ["PWCHAR","lpGuid","in"],
      ["PBLOB","pValue","in"],
      ["DWORD","nSize","in"],
      ])

    dll.add_function( 'SetHandleCount', 'DWORD',[
      ["DWORD","uNumber","in"],
      ])

    dll.add_function( 'SetHandleInformation', 'BOOL',[
      ["HANDLE","hObject","in"],
      ["DWORD","dwMask","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function( 'SetInformationJobObject', 'BOOL',[
      ["HANDLE","hJob","in"],
      ["PBLOB","JobObjectInformationClass","in"],
      ["PBLOB","lpJobObjectInformation","in"],
      ["DWORD","cbJobObjectInformationLength","in"],
      ])

    dll.add_function( 'SetLastError', 'VOID',[
      ["DWORD","dwErrCode","in"],
      ])

    dll.add_function( 'SetLocalTime', 'BOOL',[
      ["PBLOB","lpSystemTime","in"],
      ])

    dll.add_function( 'SetMailslotInfo', 'BOOL',[
      ["HANDLE","hMailslot","in"],
      ["DWORD","lReadTimeout","in"],
      ])

    dll.add_function( 'SetMessageWaitingIndicator', 'BOOL',[
      ["HANDLE","hMsgIndicator","in"],
      ["DWORD","ulMsgCount","in"],
      ])

    dll.add_function( 'SetNamedPipeHandleState', 'BOOL',[
      ["HANDLE","hNamedPipe","in"],
      ["PDWORD","lpMode","in"],
      ["PDWORD","lpMaxCollectionCount","in"],
      ["PDWORD","lpCollectDataTimeout","in"],
      ])

    dll.add_function( 'SetPriorityClass', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["DWORD","dwPriorityClass","in"],
      ])

    dll.add_function( 'SetProcessAffinityMask', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["PDWORD","dwProcessAffinityMask","in"],
      ])

    dll.add_function( 'SetProcessPriorityBoost', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["BOOL","bDisablePriorityBoost","in"],
      ])

    dll.add_function( 'SetProcessShutdownParameters', 'BOOL',[
      ["DWORD","dwLevel","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function( 'SetProcessWorkingSetSize', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["DWORD","dwMinimumWorkingSetSize","in"],
      ["DWORD","dwMaximumWorkingSetSize","in"],
      ])

    dll.add_function( 'SetProcessWorkingSetSizeEx', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["DWORD","dwMinimumWorkingSetSize","in"],
      ["DWORD","dwMaximumWorkingSetSize","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function( 'SetStdHandle', 'BOOL',[
      ["DWORD","nStdHandle","in"],
      ["HANDLE","hHandle","in"],
      ])

    dll.add_function( 'SetSystemFileCacheSize', 'BOOL',[
      ["DWORD","MinimumFileCacheSize","in"],
      ["DWORD","MaximumFileCacheSize","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function( 'SetSystemPowerState', 'BOOL',[
      ["BOOL","fSuspend","in"],
      ["BOOL","fForce","in"],
      ])

    dll.add_function( 'SetSystemTime', 'BOOL',[
      ["PBLOB","lpSystemTime","in"],
      ])

    dll.add_function( 'SetSystemTimeAdjustment', 'BOOL',[
      ["DWORD","dwTimeAdjustment","in"],
      ["BOOL","bTimeAdjustmentDisabled","in"],
      ])

    dll.add_function( 'SetTapeParameters', 'DWORD',[
      ["HANDLE","hDevice","in"],
      ["DWORD","dwOperation","in"],
      ["PBLOB","lpTapeInformation","in"],
      ])

    dll.add_function( 'SetTapePosition', 'DWORD',[
      ["HANDLE","hDevice","in"],
      ["DWORD","dwPositionMethod","in"],
      ["DWORD","dwPartition","in"],
      ["DWORD","dwOffsetLow","in"],
      ["DWORD","dwOffsetHigh","in"],
      ["BOOL","bImmediate","in"],
      ])

    #dll.add_function( 'SetThreadAffinityMask', 'PDWORD',[
    #	["HANDLE","hThread","in"],
    #	["PDWORD","dwThreadAffinityMask","in"],
    #	])

    dll.add_function( 'SetThreadContext', 'BOOL',[
      ["HANDLE","hThread","in"],
      ["PBLOB","lpContext","in"],
      ])

    dll.add_function( 'SetThreadExecutionState', 'DWORD',[
      ["DWORD","esFlags","in"],
      ])

    dll.add_function( 'SetThreadIdealProcessor', 'DWORD',[
      ["HANDLE","hThread","in"],
      ["DWORD","dwIdealProcessor","in"],
      ])

    dll.add_function( 'SetThreadPriority', 'BOOL',[
      ["HANDLE","hThread","in"],
      ["DWORD","nPriority","in"],
      ])

    dll.add_function( 'SetThreadPriorityBoost', 'BOOL',[
      ["HANDLE","hThread","in"],
      ["BOOL","bDisablePriorityBoost","in"],
      ])

    dll.add_function( 'SetThreadStackGuarantee', 'BOOL',[
      ["PDWORD","StackSizeInBytes","inout"],
      ])

    dll.add_function( 'SetTimeZoneInformation', 'BOOL',[
      ["PBLOB","lpTimeZoneInformation","in"],
      ])

    dll.add_function( 'SetTimerQueueTimer', 'DWORD',[
      ["DWORD","TimerQueue","in"],
      ["PBLOB","Callback","in"],
      ["PBLOB","Parameter","in"],
      ["DWORD","DueTime","in"],
      ["DWORD","Period","in"],
      ["BOOL","PreferIo","in"],
      ])

    dll.add_function( 'SetUnhandledExceptionFilter', 'LPVOID',[
      ["PBLOB","lpTopLevelExceptionFilter","in"],
      ])

    dll.add_function( 'SetVolumeLabelA', 'BOOL',[
      ["PCHAR","lpRootPathName","in"],
      ["PCHAR","lpVolumeName","in"],
      ])

    dll.add_function( 'SetVolumeLabelW', 'BOOL',[
      ["PWCHAR","lpRootPathName","in"],
      ["PWCHAR","lpVolumeName","in"],
      ])

    dll.add_function( 'SetVolumeMountPointA', 'BOOL',[
      ["PCHAR","lpszVolumeMountPoint","in"],
      ["PCHAR","lpszVolumeName","in"],
      ])

    dll.add_function( 'SetVolumeMountPointW', 'BOOL',[
      ["PWCHAR","lpszVolumeMountPoint","in"],
      ["PWCHAR","lpszVolumeName","in"],
      ])

    dll.add_function( 'SetWaitableTimer', 'BOOL',[
      ["HANDLE","hTimer","in"],
      ["PBLOB","lpDueTime","in"],
      ["DWORD","lPeriod","in"],
      ["PBLOB","pfnCompletionRoutine","in"],
      ["PBLOB","lpArgToCompletionRoutine","in"],
      ["BOOL","fResume","in"],
      ])

    dll.add_function( 'SetupComm', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["DWORD","dwInQueue","in"],
      ["DWORD","dwOutQueue","in"],
      ])

    dll.add_function( 'SignalObjectAndWait', 'DWORD',[
      ["HANDLE","hObjectToSignal","in"],
      ["HANDLE","hObjectToWaitOn","in"],
      ["DWORD","dwMilliseconds","in"],
      ["BOOL","bAlertable","in"],
      ])

    dll.add_function( 'SizeofResource', 'DWORD',[
      ["HANDLE","hModule","in"],
      ["HANDLE","hResInfo","in"],
      ])

    dll.add_function( 'Sleep', 'VOID',[
      ["DWORD","dwMilliseconds","in"],
      ])

    dll.add_function( 'SleepEx', 'DWORD',[
      ["DWORD","dwMilliseconds","in"],
      ["BOOL","bAlertable","in"],
      ])

    dll.add_function( 'SuspendThread', 'DWORD',[
      ["HANDLE","hThread","in"],
      ])

    dll.add_function( 'SwitchToFiber', 'VOID',[
      ["PBLOB","lpFiber","in"],
      ])

    dll.add_function( 'SwitchToThread', 'BOOL',[
      ])

    dll.add_function( 'SystemTimeToFileTime', 'BOOL',[
      ["PBLOB","lpSystemTime","in"],
      ["PBLOB","lpFileTime","out"],
      ])

    dll.add_function( 'SystemTimeToTzSpecificLocalTime', 'BOOL',[
      ["PBLOB","lpTimeZoneInformation","in"],
      ["PBLOB","lpUniversalTime","in"],
      ["PBLOB","lpLocalTime","out"],
      ])

    dll.add_function( 'TerminateJobObject', 'BOOL',[
      ["HANDLE","hJob","in"],
      ["DWORD","uExitCode","in"],
      ])

    dll.add_function( 'TerminateProcess', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["DWORD","uExitCode","in"],
      ])

    dll.add_function( 'TerminateThread', 'BOOL',[
      ["HANDLE","hThread","in"],
      ["DWORD","dwExitCode","in"],
      ])

    dll.add_function( 'TlsAlloc', 'DWORD',[
      ])

    dll.add_function( 'TlsFree', 'BOOL',[
      ["DWORD","dwTlsIndex","in"],
      ])

    dll.add_function( 'TlsGetValue', 'LPVOID',[
      ["DWORD","dwTlsIndex","in"],
      ])

    dll.add_function( 'TlsSetValue', 'BOOL',[
      ["DWORD","dwTlsIndex","in"],
      ["PBLOB","lpTlsValue","in"],
      ])

    dll.add_function( 'TransactNamedPipe', 'BOOL',[
      ["HANDLE","hNamedPipe","in"],
      ["PBLOB","lpInBuffer","in"],
      ["DWORD","nInBufferSize","in"],
      ["PBLOB","lpOutBuffer","out"],
      ["DWORD","nOutBufferSize","in"],
      ["PDWORD","lpBytesRead","out"],
      ["PBLOB","lpOverlapped","inout"],
      ])

    dll.add_function( 'TransmitCommChar', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["BYTE","cChar","in"],
      ])

    dll.add_function( 'TryEnterCriticalSection', 'BOOL',[
      ["PBLOB","lpCriticalSection","inout"],
      ])

    dll.add_function( 'TzSpecificLocalTimeToSystemTime', 'BOOL',[
      ["PBLOB","lpTimeZoneInformation","in"],
      ["PBLOB","lpLocalTime","in"],
      ["PBLOB","lpUniversalTime","out"],
      ])

    dll.add_function( 'UnhandledExceptionFilter', 'DWORD',[
      ["PBLOB","ExceptionInfo","in"],
      ])

    dll.add_function( 'UnlockFile', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["DWORD","dwFileOffsetLow","in"],
      ["DWORD","dwFileOffsetHigh","in"],
      ["DWORD","nNumberOfBytesToUnlockLow","in"],
      ["DWORD","nNumberOfBytesToUnlockHigh","in"],
      ])

    dll.add_function( 'UnlockFileEx', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["DWORD","dwReserved","inout"],
      ["DWORD","nNumberOfBytesToUnlockLow","in"],
      ["DWORD","nNumberOfBytesToUnlockHigh","in"],
      ["PBLOB","lpOverlapped","inout"],
      ])

    dll.add_function( 'UnmapViewOfFile', 'BOOL',[
      ["PBLOB","lpBaseAddress","in"],
      ])

    dll.add_function( 'UnregisterWait', 'BOOL',[
      ["DWORD","WaitHandle","in"],
      ])

    dll.add_function( 'UnregisterWaitEx', 'BOOL',[
      ["DWORD","WaitHandle","in"],
      ["DWORD","CompletionEvent","in"],
      ])

    dll.add_function( 'UpdateResourceA', 'BOOL',[
      ["HANDLE","hUpdate","in"],
      ["PCHAR","lpType","in"],
      ["PCHAR","lpName","in"],
      ["WORD","wLanguage","in"],
      ["PBLOB","lpData","in"],
      ["DWORD","cb","in"],
      ])

    dll.add_function( 'UpdateResourceW', 'BOOL',[
      ["HANDLE","hUpdate","in"],
      ["PWCHAR","lpType","in"],
      ["PWCHAR","lpName","in"],
      ["WORD","wLanguage","in"],
      ["PBLOB","lpData","in"],
      ["DWORD","cb","in"],
      ])

    dll.add_function( 'VerifyVersionInfoA', 'BOOL',[
      ["PBLOB","lpVersionInformation","inout"],
      ["DWORD","dwTypeMask","in"],
      ["PBLOB","dwlConditionMask","in"],
      ])

    dll.add_function( 'VerifyVersionInfoW', 'BOOL',[
      ["PBLOB","lpVersionInformation","inout"],
      ["DWORD","dwTypeMask","in"],
      ["PBLOB","dwlConditionMask","in"],
      ])

    dll.add_function( 'VirtualAlloc', 'LPVOID',[
      ["LPVOID","lpAddress","in"],
      ["DWORD","dwSize","in"],
      ["DWORD","flAllocationType","in"],
      ["DWORD","flProtect","in"],
      ])

    dll.add_function( 'VirtualAllocEx', 'LPVOID',[
      ["HANDLE","hProcess","in"],
      ["LPVOID","lpAddress","in"],
      ["DWORD","dwSize","in"],
      ["DWORD","flAllocationType","in"],
      ["DWORD","flProtect","in"],
      ])

    dll.add_function( 'VirtualFree', 'BOOL',[
      ["LPVOID","lpAddress","in"],
      ["DWORD","dwSize","in"],
      ["DWORD","dwFreeType","in"],
      ])

    dll.add_function( 'VirtualFreeEx', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["LPVOID","lpAddress","in"],
      ["DWORD","dwSize","in"],
      ["DWORD","dwFreeType","in"],
      ])

    dll.add_function( 'VirtualLock', 'BOOL',[
      ["LPVOID","lpAddress","in"],
      ["DWORD","dwSize","in"],
      ])

    dll.add_function( 'VirtualProtect', 'BOOL',[
      ["LPVOID","lpAddress","in"],
      ["DWORD","dwSize","in"],
      ["DWORD","flNewProtect","in"],
      ["PDWORD","lpflOldProtect","out"],
      ])

    dll.add_function( 'VirtualProtectEx', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["LPVOID","lpAddress","in"],
      ["DWORD","dwSize","in"],
      ["DWORD","flNewProtect","in"],
      ["PDWORD","lpflOldProtect","out"],
      ])

    dll.add_function( 'VirtualQuery', 'DWORD',[
      ["LPVOID","lpAddress","in"],
      ["PBLOB","lpBuffer","out"],
      ["DWORD","dwLength","in"],
      ])

    dll.add_function( 'VirtualQueryEx', 'DWORD',[
      ["HANDLE","hProcess","in"],
      ["LPVOID","lpAddress","in"],
      ["PBLOB","lpBuffer","out"],
      ["DWORD","dwLength","in"],
      ])

    dll.add_function( 'VirtualUnlock', 'BOOL',[
      ["LPVOID","lpAddress","in"],
      ["DWORD","dwSize","in"],
      ])

    dll.add_function( 'WTSGetActiveConsoleSessionId', 'DWORD',[
      ])

    dll.add_function( 'WaitCommEvent', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PDWORD","lpEvtMask","inout"],
      ["PBLOB","lpOverlapped","inout"],
      ])

    dll.add_function( 'WaitForDebugEvent', 'BOOL',[
      ["PBLOB","lpDebugEvent","in"],
      ["DWORD","dwMilliseconds","in"],
      ])

    dll.add_function( 'WaitForMultipleObjects', 'DWORD',[
      ["DWORD","nCount","in"],
      ["PDWORD","lpHandles","in"],
      ["BOOL","bWaitAll","in"],
      ["DWORD","dwMilliseconds","in"],
      ])

    dll.add_function( 'WaitForMultipleObjectsEx', 'DWORD',[
      ["DWORD","nCount","in"],
      ["PDWORD","lpHandles","in"],
      ["BOOL","bWaitAll","in"],
      ["DWORD","dwMilliseconds","in"],
      ["BOOL","bAlertable","in"],
      ])

    dll.add_function( 'WaitForSingleObject', 'DWORD',[
      ["HANDLE","hHandle","in"],
      ["DWORD","dwMilliseconds","in"],
      ])

    dll.add_function( 'WaitForSingleObjectEx', 'DWORD',[
      ["HANDLE","hHandle","in"],
      ["DWORD","dwMilliseconds","in"],
      ["BOOL","bAlertable","in"],
      ])

    dll.add_function( 'WaitNamedPipeA', 'BOOL',[
      ["PCHAR","lpNamedPipeName","in"],
      ["DWORD","nTimeOut","in"],
      ])

    dll.add_function( 'WaitNamedPipeW', 'BOOL',[
      ["PWCHAR","lpNamedPipeName","in"],
      ["DWORD","nTimeOut","in"],
      ])

    dll.add_function( 'WinExec', 'DWORD',[
      ["PCHAR","lpCmdLine","in"],
      ["DWORD","uCmdShow","in"],
      ])

    dll.add_function( 'Wow64DisableWow64FsRedirection', 'BOOL',[
      ["PBLOB","OldValue","out"],
      ])

    dll.add_function( 'Wow64EnableWow64FsRedirection', 'BOOL',[
      ["BOOL","Wow64FsEnableRedirection","in"],
      ])

    dll.add_function( 'Wow64RevertWow64FsRedirection', 'BOOL',[
      ["PBLOB","OlValue","in"],
      ])

    dll.add_function( 'WriteFile', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpBuffer","in"],
      ["DWORD","nNumberOfBytesToWrite","in"],
      ["PDWORD","lpNumberOfBytesWritten","out"],
      ["PBLOB","lpOverlapped","inout"],
      ])

    dll.add_function( 'WriteFileEx', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpBuffer","in"],
      ["DWORD","nNumberOfBytesToWrite","in"],
      ["PBLOB","lpOverlapped","inout"],
      ["PBLOB","lpCompletionRoutine","in"],
      ])

    dll.add_function( 'WriteFileGather', 'BOOL',[
      ["HANDLE","hFile","in"],
      ["PBLOB","aSegmentArray[]","in"],
      ["DWORD","nNumberOfBytesToWrite","in"],
      ["PDWORD","lpReserved","inout"],
      ["PBLOB","lpOverlapped","inout"],
      ])

    dll.add_function( 'WritePrivateProfileSectionA', 'BOOL',[
      ["PCHAR","lpAppName","in"],
      ["PCHAR","lpString","in"],
      ["PCHAR","lpFileName","in"],
      ])

    dll.add_function( 'WritePrivateProfileSectionW', 'BOOL',[
      ["PWCHAR","lpAppName","in"],
      ["PWCHAR","lpString","in"],
      ["PWCHAR","lpFileName","in"],
      ])

    dll.add_function( 'WritePrivateProfileStringA', 'BOOL',[
      ["PCHAR","lpAppName","in"],
      ["PCHAR","lpKeyName","in"],
      ["PCHAR","lpString","in"],
      ["PCHAR","lpFileName","in"],
      ])

    dll.add_function( 'WritePrivateProfileStringW', 'BOOL',[
      ["PWCHAR","lpAppName","in"],
      ["PWCHAR","lpKeyName","in"],
      ["PWCHAR","lpString","in"],
      ["PWCHAR","lpFileName","in"],
      ])

    dll.add_function( 'WritePrivateProfileStructA', 'BOOL',[
      ["PCHAR","lpszSection","in"],
      ["PCHAR","lpszKey","in"],
      ["PBLOB","lpStruct","in"],
      ["DWORD","uSizeStruct","in"],
      ["PCHAR","szFile","in"],
      ])

    dll.add_function( 'WritePrivateProfileStructW', 'BOOL',[
      ["PWCHAR","lpszSection","in"],
      ["PWCHAR","lpszKey","in"],
      ["PBLOB","lpStruct","in"],
      ["DWORD","uSizeStruct","in"],
      ["PWCHAR","szFile","in"],
      ])

    dll.add_function( 'WriteProcessMemory', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["LPVOID","lpBaseAddress","in"],
      ["PBLOB","lpBuffer","in"],
      ["DWORD","nSize","in"],
      ["PDWORD","lpNumberOfBytesWritten","out"],
      ])

    dll.add_function( 'WriteProfileSectionA', 'BOOL',[
      ["PCHAR","lpAppName","in"],
      ["PCHAR","lpString","in"],
      ])

    dll.add_function( 'WriteProfileSectionW', 'BOOL',[
      ["PWCHAR","lpAppName","in"],
      ["PWCHAR","lpString","in"],
      ])

    dll.add_function( 'WriteProfileStringA', 'BOOL',[
      ["PCHAR","lpAppName","in"],
      ["PCHAR","lpKeyName","in"],
      ["PCHAR","lpString","in"],
      ])

    dll.add_function( 'WriteProfileStringW', 'BOOL',[
      ["PWCHAR","lpAppName","in"],
      ["PWCHAR","lpKeyName","in"],
      ["PWCHAR","lpString","in"],
      ])

    dll.add_function( 'WriteTapemark', 'DWORD',[
      ["HANDLE","hDevice","in"],
      ["DWORD","dwTapemarkType","in"],
      ["DWORD","dwTapemarkCount","in"],
      ["BOOL","bImmediate","in"],
      ])

    dll.add_function( 'ZombifyActCtx', 'BOOL',[
      ["HANDLE","hActCtx","inout"],
      ])

    dll.add_function( '_hread', 'DWORD',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpBuffer","out"],
      ["DWORD","lBytes","in"],
      ])

    dll.add_function( '_hwrite', 'DWORD',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpBuffer","in"],
      ["DWORD","lBytes","in"],
      ])

    dll.add_function( '_lclose', 'DWORD',[
      ["HANDLE","hFile","in"],
      ])

    dll.add_function( '_lcreat', 'DWORD',[
      ["PCHAR","lpPathName","in"],
      ["DWORD","iAttribute","in"],
      ])

    dll.add_function( '_llseek', 'DWORD',[
      ["HANDLE","hFile","in"],
      ["DWORD","lOffset","in"],
      ["DWORD","iOrigin","in"],
      ])

    dll.add_function( '_lopen', 'DWORD',[
      ["PCHAR","lpPathName","in"],
      ["DWORD","iReadWrite","in"],
      ])

    dll.add_function( '_lread', 'DWORD',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpBuffer","out"],
      ["DWORD","uBytes","in"],
      ])

    dll.add_function( '_lwrite', 'DWORD',[
      ["HANDLE","hFile","in"],
      ["PBLOB","lpBuffer","in"],
      ["DWORD","uBytes","in"],
      ])

    #dll.add_function( 'lstrcatA', 'PCHAR',[
    #	["PCHAR","lpString1","inout"],
    #	["PCHAR","lpString2","in"],
    #	])

    #dll.add_function( 'lstrcatW', 'PWCHAR',[
    #	["PWCHAR","lpString1","inout"],
    #	["PWCHAR","lpString2","in"],
    #	])

    dll.add_function( 'lstrcmpA', 'DWORD',[
      ["PCHAR","lpString1","in"],
      ["PCHAR","lpString2","in"],
      ])

    dll.add_function( 'lstrcmpW', 'DWORD',[
      ["PWCHAR","lpString1","in"],
      ["PWCHAR","lpString2","in"],
      ])

    dll.add_function( 'lstrcmpiA', 'DWORD',[
      ["PCHAR","lpString1","in"],
      ["PCHAR","lpString2","in"],
      ])

    dll.add_function( 'lstrcmpiW', 'DWORD',[
      ["PWCHAR","lpString1","in"],
      ["PWCHAR","lpString2","in"],
      ])

    #dll.add_function( 'lstrcpyA', 'PCHAR',[
    #	["PCHAR","lpString1","out"],
    #	["PCHAR","lpString2","in"],
    #	])

    #dll.add_function( 'lstrcpyW', 'PWCHAR',[
    #	["PWCHAR","lpString1","out"],
    #	["PWCHAR","lpString2","in"],
    #	])

    #dll.add_function( 'lstrcpynA', 'PCHAR',[
    #	["PCHAR","lpString1","out"],
    #	["PCHAR","lpString2","in"],
    #	["DWORD","iMaxLength","in"],
    #	])

    #dll.add_function( 'lstrcpynW', 'PWCHAR',[
    #	["PWCHAR","lpString1","out"],
    #	["PWCHAR","lpString2","in"],
    #	["DWORD","iMaxLength","in"],
    #	])

    dll.add_function( 'lstrlenA', 'DWORD',[
      ["LPVOID","lpString","in"],
      ])

    dll.add_function( 'lstrlenW', 'DWORD',[
      ["LPVOID","lpString","in"],
      ])


    dll.add_function('CreateToolhelp32Snapshot', 'DWORD',[
      ["DWORD","dwFlags","in"],
      ["DWORD","th32ProcessID","in"],
      ])

    dll.add_function('Heap32First', 'BOOL',[
      ["PBLOB","lphe","inout"],
      ["DWORD","th32ProcessID","in"],
      ["PDWORD","th32HeapID","inout"],
      ])

    dll.add_function('Heap32ListFirst', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lphl","inout"],
      ])

    dll.add_function('Heap32ListNext', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lphl","inout"],
      ])

    dll.add_function('Heap32Next', 'BOOL',[
      ["PBLOB","lphe","inout"],
      ])

    dll.add_function('Module32First', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lpme","inout"],
      ])

    dll.add_function('Module32FirstW', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lpme","inout"],
      ])

    dll.add_function('Module32Next', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lpme","inout"],
      ])

    dll.add_function('Module32NextW', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lpme","inout"],
      ])

    dll.add_function('Process32First', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lppe","inout"],
      ])

    dll.add_function('Process32FirstW', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lppe","inout"],
      ])

    dll.add_function('Process32Next', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lppe","inout"],
      ])

    dll.add_function('Process32NextW', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lppe","inout"],
      ])

    dll.add_function('Thread32First', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lpte","inout"],
      ])

    dll.add_function('Thread32Next', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lpte","inout"],
      ])

    dll.add_function('Toolhelp32ReadProcessMemory', 'BOOL',[
      ["DWORD","th32ProcessID","in"],
      ["PBLOB","lpBaseAddress","inout"],
      ["PBLOB","lpBuffer","inout"],
      ["DWORD","cbRead","in"],
      ["PDWORD","lpNumberOfBytesRead","in"],
      ])

    dll.add_function('CreateToolhelp32Snapshot', 'DWORD',[
      ["DWORD","dwFlags","in"],
      ["DWORD","th32ProcessID","in"],
      ])

    dll.add_function('Heap32First', 'BOOL',[
      ["PBLOB","lphe","inout"],
      ["DWORD","th32ProcessID","in"],
      ["PDWORD","th32HeapID","inout"],
      ])

    dll.add_function('Heap32ListFirst', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lphl","inout"],
      ])

    dll.add_function('Heap32ListNext', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lphl","inout"],
      ])

    dll.add_function('Heap32Next', 'BOOL',[
      ["PBLOB","lphe","inout"],
      ])

    dll.add_function('Module32First', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lpme","inout"],
      ])

    dll.add_function('Module32FirstW', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lpme","inout"],
      ])

    dll.add_function('Module32Next', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lpme","inout"],
      ])

    dll.add_function('Module32NextW', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lpme","inout"],
      ])

    dll.add_function('Process32First', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lppe","inout"],
      ])

    dll.add_function('Process32FirstW', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lppe","inout"],
      ])

    dll.add_function('Process32Next', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lppe","inout"],
      ])

    dll.add_function('Process32NextW', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lppe","inout"],
      ])

    dll.add_function('Thread32First', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lpte","inout"],
      ])

    dll.add_function('Thread32Next', 'BOOL',[
      ["DWORD","hSnapshot","in"],
      ["PBLOB","lpte","inout"],
      ])

    dll.add_function('Toolhelp32ReadProcessMemory', 'BOOL',[
      ["DWORD","th32ProcessID","in"],
      ["PBLOB","lpBaseAddress","inout"],
      ["PBLOB","lpBuffer","inout"],
      ["DWORD","cbRead","in"],
      ["PDWORD","lpNumberOfBytesRead","in"],
      ])

    return dll
  end

end

end; end; end; end; end; end; end


