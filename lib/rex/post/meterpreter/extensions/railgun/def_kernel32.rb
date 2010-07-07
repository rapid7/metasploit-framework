module Rex
module Post
module Meterpreter
module Extensions
module Railgun

class Def_kernel32
	def self.add_imports(railgun)
		railgun.add_function('kernel32',  'ActivateActCtx', 'BOOL',[
			["DWORD","hActCtx","inout"],
			["PBLOB","lpCookie","out"],
			])
		
		railgun.add_function('kernel32',  'AddAtomA', 'WORD',[
			["PCHAR","lpString","in"],
			])
		
		railgun.add_function('kernel32',  'AddAtomW', 'WORD',[
			["PWCHAR","lpString","in"],
			])
		
		railgun.add_function('kernel32',  'AddRefActCtx', 'VOID',[
			["DWORD","hActCtx","inout"],
			])
		
		railgun.add_function('kernel32',  'AddVectoredContinueHandler', 'PBLOB',[
			["DWORD","First","in"],
			["PBLOB","Handler","in"],
			])
		
		railgun.add_function('kernel32',  'AddVectoredExceptionHandler', 'PBLOB',[
			["DWORD","First","in"],
			["PBLOB","Handler","in"],
			])
		
		railgun.add_function('kernel32',  'AllocateUserPhysicalPages', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","NumberOfPages","inout"],
			["PBLOB","PageArray","out"],
			])
		
		railgun.add_function('kernel32',  'AreFileApisANSI', 'BOOL',[
			])
		
		railgun.add_function('kernel32',  'AssignProcessToJobObject', 'BOOL',[
			["DWORD","hJob","in"],
			["DWORD","hProcess","in"],
			])
		
		railgun.add_function('kernel32',  'BackupRead', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","nNumberOfBytesToRead","in"],
			["PDWORD","lpNumberOfBytesRead","out"],
			["BOOL","bAbort","in"],
			["BOOL","bProcessSecurity","in"],
			["PBLOB","lpContext","inout"],
			])
		
		railgun.add_function('kernel32',  'BackupSeek', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwLowBytesToSeek","in"],
			["DWORD","dwHighBytesToSeek","in"],
			["PDWORD","lpdwLowByteSeeked","out"],
			["PDWORD","lpdwHighByteSeeked","out"],
			["PBLOB","lpContext","inout"],
			])
		
		railgun.add_function('kernel32',  'BackupWrite', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","in"],
			["DWORD","nNumberOfBytesToWrite","in"],
			["PDWORD","lpNumberOfBytesWritten","out"],
			["BOOL","bAbort","in"],
			["BOOL","bProcessSecurity","in"],
			["PBLOB","lpContext","inout"],
			])
		
		railgun.add_function('kernel32',  'Beep', 'BOOL',[
			["DWORD","dwFreq","in"],
			["DWORD","dwDuration","in"],
			])
		
		railgun.add_function('kernel32',  'BeginUpdateResourceA', 'DWORD',[
			["PCHAR","pFileName","in"],
			["BOOL","bDeleteExistingResources","in"],
			])
		
		railgun.add_function('kernel32',  'BeginUpdateResourceW', 'DWORD',[
			["PWCHAR","pFileName","in"],
			["BOOL","bDeleteExistingResources","in"],
			])
		
		railgun.add_function('kernel32',  'BindIoCompletionCallback', 'BOOL',[
			["DWORD","FileHandle","in"],
			["PBLOB","Function","in"],
			["DWORD","Flags","in"],
			])
		
		railgun.add_function('kernel32',  'BuildCommDCBA', 'BOOL',[
			["PCHAR","lpDef","in"],
			["PBLOB","lpDCB","out"],
			])
		
		railgun.add_function('kernel32',  'BuildCommDCBAndTimeoutsA', 'BOOL',[
			["PCHAR","lpDef","in"],
			["PBLOB","lpDCB","out"],
			["PBLOB","lpCommTimeouts","out"],
			])
		
		railgun.add_function('kernel32',  'BuildCommDCBAndTimeoutsW', 'BOOL',[
			["PWCHAR","lpDef","in"],
			["PBLOB","lpDCB","out"],
			["PBLOB","lpCommTimeouts","out"],
			])
		
		railgun.add_function('kernel32',  'BuildCommDCBW', 'BOOL',[
			["PWCHAR","lpDef","in"],
			["PBLOB","lpDCB","out"],
			])
		
		railgun.add_function('kernel32',  'CallNamedPipeA', 'BOOL',[
			["PCHAR","lpNamedPipeName","in"],
			["PBLOB","lpInBuffer","in"],
			["DWORD","nInBufferSize","in"],
			["PBLOB","lpOutBuffer","out"],
			["DWORD","nOutBufferSize","in"],
			["PDWORD","lpBytesRead","out"],
			["DWORD","nTimeOut","in"],
			])
		
		railgun.add_function('kernel32',  'CallNamedPipeW', 'BOOL',[
			["PWCHAR","lpNamedPipeName","in"],
			["PBLOB","lpInBuffer","in"],
			["DWORD","nInBufferSize","in"],
			["PBLOB","lpOutBuffer","out"],
			["DWORD","nOutBufferSize","in"],
			["PDWORD","lpBytesRead","out"],
			["DWORD","nTimeOut","in"],
			])
		
		railgun.add_function('kernel32',  'CancelDeviceWakeupRequest', 'BOOL',[
			["DWORD","hDevice","in"],
			])
		
		railgun.add_function('kernel32',  'CancelIo', 'BOOL',[
			["DWORD","hFile","in"],
			])
		
		railgun.add_function('kernel32',  'CancelTimerQueueTimer', 'BOOL',[
			["DWORD","TimerQueue","in"],
			["DWORD","Timer","in"],
			])
		
		railgun.add_function('kernel32',  'CancelWaitableTimer', 'BOOL',[
			["DWORD","hTimer","in"],
			])
		
		railgun.add_function('kernel32',  'ChangeTimerQueueTimer', 'BOOL',[
			["DWORD","TimerQueue","in"],
			["DWORD","Timer","inout"],
			["DWORD","DueTime","in"],
			["DWORD","Period","in"],
			])
		
		railgun.add_function('kernel32',  'CheckNameLegalDOS8Dot3A', 'BOOL',[
			["PCHAR","lpName","in"],
			["PCHAR","lpOemName","out"],
			["DWORD","OemNameSize","in"],
			["PBLOB","pbNameContainsSpaces","out"],
			["PBLOB","pbNameLegal","out"],
			])
		
		railgun.add_function('kernel32',  'CheckNameLegalDOS8Dot3W', 'BOOL',[
			["PWCHAR","lpName","in"],
			["PCHAR","lpOemName","out"],
			["DWORD","OemNameSize","in"],
			["PBLOB","pbNameContainsSpaces","out"],
			["PBLOB","pbNameLegal","out"],
			])
		
		railgun.add_function('kernel32',  'CheckRemoteDebuggerPresent', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","pbDebuggerPresent","out"],
			])
		
		railgun.add_function('kernel32',  'ClearCommBreak', 'BOOL',[
			["DWORD","hFile","in"],
			])
		
		railgun.add_function('kernel32',  'ClearCommError', 'BOOL',[
			["DWORD","hFile","in"],
			["PDWORD","lpErrors","out"],
			["PBLOB","lpStat","out"],
			])
		
		railgun.add_function('kernel32',  'CloseHandle', 'BOOL',[
			["DWORD","hObject","in"],
			])
		
		railgun.add_function('kernel32',  'CommConfigDialogA', 'BOOL',[
			["PCHAR","lpszName","in"],
			["DWORD","hWnd","in"],
			["PBLOB","lpCC","inout"],
			])
		
		railgun.add_function('kernel32',  'CommConfigDialogW', 'BOOL',[
			["PWCHAR","lpszName","in"],
			["DWORD","hWnd","in"],
			["PBLOB","lpCC","inout"],
			])
		
		railgun.add_function('kernel32',  'CompareFileTime', 'DWORD',[
			["PBLOB","lpFileTime1","in"],
			["PBLOB","lpFileTime2","in"],
			])
		
		railgun.add_function('kernel32',  'ConnectNamedPipe', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			["PBLOB","lpOverlapped","inout"],
			])
		
		railgun.add_function('kernel32',  'ContinueDebugEvent', 'BOOL',[
			["DWORD","dwProcessId","in"],
			["DWORD","dwThreadId","in"],
			["DWORD","dwContinueStatus","in"],
			])
		
		railgun.add_function('kernel32',  'ConvertFiberToThread', 'BOOL',[
			])
		
		railgun.add_function('kernel32',  'ConvertThreadToFiber', 'PBLOB',[
			["PBLOB","lpParameter","in"],
			])
		
		railgun.add_function('kernel32',  'ConvertThreadToFiberEx', 'PBLOB',[
			["PBLOB","lpParameter","in"],
			["DWORD","dwFlags","in"],
			])
		
		railgun.add_function('kernel32',  'CopyFileA', 'BOOL',[
			["PCHAR","lpExistingFileName","in"],
			["PCHAR","lpNewFileName","in"],
			["BOOL","bFailIfExists","in"],
			])
		
		railgun.add_function('kernel32',  'CopyFileExA', 'BOOL',[
			["PCHAR","lpExistingFileName","in"],
			["PCHAR","lpNewFileName","in"],
			["PBLOB","lpProgressRoutine","in"],
			["PBLOB","lpData","in"],
			["PBLOB","pbCancel","in"],
			["DWORD","dwCopyFlags","in"],
			])
		
		railgun.add_function('kernel32',  'CopyFileExW', 'BOOL',[
			["PWCHAR","lpExistingFileName","in"],
			["PWCHAR","lpNewFileName","in"],
			["PBLOB","lpProgressRoutine","in"],
			["PBLOB","lpData","in"],
			["PBLOB","pbCancel","in"],
			["DWORD","dwCopyFlags","in"],
			])
		
		railgun.add_function('kernel32',  'CopyFileW', 'BOOL',[
			["PWCHAR","lpExistingFileName","in"],
			["PWCHAR","lpNewFileName","in"],
			["BOOL","bFailIfExists","in"],
			])
		
		railgun.add_function('kernel32',  'CreateActCtxA', 'DWORD',[
			["PBLOB","pActCtx","in"],
			])
		
		railgun.add_function('kernel32',  'CreateActCtxW', 'DWORD',[
			["PBLOB","pActCtx","in"],
			])
		
		railgun.add_function('kernel32',  'CreateDirectoryA', 'BOOL',[
			["PCHAR","lpPathName","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])
		
		railgun.add_function('kernel32',  'CreateDirectoryExA', 'BOOL',[
			["PCHAR","lpTemplateDirectory","in"],
			["PCHAR","lpNewDirectory","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])
		
		railgun.add_function('kernel32',  'CreateDirectoryExW', 'BOOL',[
			["PWCHAR","lpTemplateDirectory","in"],
			["PWCHAR","lpNewDirectory","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])
		
		railgun.add_function('kernel32',  'CreateDirectoryW', 'BOOL',[
			["PWCHAR","lpPathName","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])
		
		railgun.add_function('kernel32',  'CreateEventA', 'DWORD',[
			["PBLOB","lpEventAttributes","in"],
			["BOOL","bManualReset","in"],
			["BOOL","bInitialState","in"],
			["PCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'CreateEventW', 'DWORD',[
			["PBLOB","lpEventAttributes","in"],
			["BOOL","bManualReset","in"],
			["BOOL","bInitialState","in"],
			["PWCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'CreateFiber', 'PBLOB',[
			["DWORD","dwStackSize","in"],
			["PBLOB","lpStartAddress","in"],
			["PBLOB","lpParameter","in"],
			])
		
		railgun.add_function('kernel32',  'CreateFiberEx', 'PBLOB',[
			["DWORD","dwStackCommitSize","in"],
			["DWORD","dwStackReserveSize","in"],
			["DWORD","dwFlags","in"],
			["PBLOB","lpStartAddress","in"],
			["PBLOB","lpParameter","in"],
			])
		
		railgun.add_function('kernel32',  'CreateFileA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			["DWORD","dwDesiredAccess","in"],
			["DWORD","dwShareMode","in"],
			["PBLOB","lpSecurityAttributes","in"],
			["DWORD","dwCreationDisposition","in"],
			["DWORD","dwFlagsAndAttributes","in"],
			["DWORD","hTemplateFile","in"],
			])
		
		railgun.add_function('kernel32',  'CreateFileMappingA', 'DWORD',[
			["DWORD","hFile","in"],
			["PBLOB","lpFileMappingAttributes","in"],
			["DWORD","flProtect","in"],
			["DWORD","dwMaximumSizeHigh","in"],
			["DWORD","dwMaximumSizeLow","in"],
			["PCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'CreateFileMappingW', 'DWORD',[
			["DWORD","hFile","in"],
			["PBLOB","lpFileMappingAttributes","in"],
			["DWORD","flProtect","in"],
			["DWORD","dwMaximumSizeHigh","in"],
			["DWORD","dwMaximumSizeLow","in"],
			["PWCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'CreateFileW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			["DWORD","dwDesiredAccess","in"],
			["DWORD","dwShareMode","in"],
			["PBLOB","lpSecurityAttributes","in"],
			["DWORD","dwCreationDisposition","in"],
			["DWORD","dwFlagsAndAttributes","in"],
			["DWORD","hTemplateFile","in"],
			])
		
		railgun.add_function('kernel32',  'CreateHardLinkA', 'BOOL',[
			["PCHAR","lpFileName","in"],
			["PCHAR","lpExistingFileName","in"],
			["PBLOB","lpSecurityAttributes","inout"],
			])
		
		railgun.add_function('kernel32',  'CreateHardLinkW', 'BOOL',[
			["PWCHAR","lpFileName","in"],
			["PWCHAR","lpExistingFileName","in"],
			["PBLOB","lpSecurityAttributes","inout"],
			])
		
		railgun.add_function('kernel32',  'CreateIoCompletionPort', 'DWORD',[
			["DWORD","FileHandle","in"],
			["DWORD","ExistingCompletionPort","in"],
			["PDWORD","CompletionKey","in"],
			["DWORD","NumberOfConcurrentThreads","in"],
			])
		
		railgun.add_function('kernel32',  'CreateJobObjectA', 'DWORD',[
			["PBLOB","lpJobAttributes","in"],
			["PCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'CreateJobObjectW', 'DWORD',[
			["PBLOB","lpJobAttributes","in"],
			["PWCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'CreateJobSet', 'BOOL',[
			["DWORD","NumJob","in"],
			["PBLOB","UserJobSet","in"],
			["DWORD","Flags","in"],
			])
		
		railgun.add_function('kernel32',  'CreateMailslotA', 'DWORD',[
			["PCHAR","lpName","in"],
			["DWORD","nMaxMessageSize","in"],
			["DWORD","lReadTimeout","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])
		
		railgun.add_function('kernel32',  'CreateMailslotW', 'DWORD',[
			["PWCHAR","lpName","in"],
			["DWORD","nMaxMessageSize","in"],
			["DWORD","lReadTimeout","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])
		
		railgun.add_function('kernel32',  'CreateMemoryResourceNotification', 'DWORD',[
			["PDWORD","NotificationType","in"],
			])
		
		railgun.add_function('kernel32',  'CreateMutexA', 'DWORD',[
			["PBLOB","lpMutexAttributes","in"],
			["BOOL","bInitialOwner","in"],
			["PCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'CreateMutexW', 'DWORD',[
			["PBLOB","lpMutexAttributes","in"],
			["BOOL","bInitialOwner","in"],
			["PWCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'CreateNamedPipeA', 'DWORD',[
			["PCHAR","lpName","in"],
			["DWORD","dwOpenMode","in"],
			["DWORD","dwPipeMode","in"],
			["DWORD","nMaxInstances","in"],
			["DWORD","nOutBufferSize","in"],
			["DWORD","nInBufferSize","in"],
			["DWORD","nDefaultTimeOut","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])
		
		railgun.add_function('kernel32',  'CreateNamedPipeW', 'DWORD',[
			["PWCHAR","lpName","in"],
			["DWORD","dwOpenMode","in"],
			["DWORD","dwPipeMode","in"],
			["DWORD","nMaxInstances","in"],
			["DWORD","nOutBufferSize","in"],
			["DWORD","nInBufferSize","in"],
			["DWORD","nDefaultTimeOut","in"],
			["PBLOB","lpSecurityAttributes","in"],
			])
		
		railgun.add_function('kernel32',  'CreatePipe', 'BOOL',[
			["PDWORD","hReadPipe","out"],
			["PDWORD","hWritePipe","out"],
			["PBLOB","lpPipeAttributes","in"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'CreateProcessA', 'BOOL',[
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
		
		railgun.add_function('kernel32',  'CreateProcessW', 'BOOL',[
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
		
		railgun.add_function('kernel32',  'CreateRemoteThread', 'DWORD',[
			["DWORD","hProcess","in"],
			["PBLOB","lpThreadAttributes","in"],
			["DWORD","dwStackSize","in"],
			["PBLOB","lpStartAddress","in"],
			["PBLOB","lpParameter","in"],
			["DWORD","dwCreationFlags","in"],
			["PDWORD","lpThreadId","out"],
			])
		
		railgun.add_function('kernel32',  'CreateSemaphoreA', 'DWORD',[
			["PBLOB","lpSemaphoreAttributes","in"],
			["DWORD","lInitialCount","in"],
			["DWORD","lMaximumCount","in"],
			["PCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'CreateSemaphoreW', 'DWORD',[
			["PBLOB","lpSemaphoreAttributes","in"],
			["DWORD","lInitialCount","in"],
			["DWORD","lMaximumCount","in"],
			["PWCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'CreateTapePartition', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwPartitionMethod","in"],
			["DWORD","dwCount","in"],
			["DWORD","dwSize","in"],
			])
		
		railgun.add_function('kernel32',  'CreateThread', 'DWORD',[
			["PBLOB","lpThreadAttributes","in"],
			["DWORD","dwStackSize","in"],
			["PBLOB","lpStartAddress","in"],
			["PBLOB","lpParameter","in"],
			["DWORD","dwCreationFlags","in"],
			["PDWORD","lpThreadId","out"],
			])
		
		railgun.add_function('kernel32',  'CreateTimerQueue', 'DWORD',[
			])
		
		railgun.add_function('kernel32',  'CreateTimerQueueTimer', 'BOOL',[
			["PDWORD","phNewTimer","out"],
			["DWORD","TimerQueue","in"],
			["PBLOB","Callback","in"],
			["PBLOB","Parameter","in"],
			["DWORD","DueTime","in"],
			["DWORD","Period","in"],
			["DWORD","Flags","in"],
			])
		
		railgun.add_function('kernel32',  'CreateWaitableTimerA', 'DWORD',[
			["PBLOB","lpTimerAttributes","in"],
			["BOOL","bManualReset","in"],
			["PCHAR","lpTimerName","in"],
			])
		
		railgun.add_function('kernel32',  'CreateWaitableTimerW', 'DWORD',[
			["PBLOB","lpTimerAttributes","in"],
			["BOOL","bManualReset","in"],
			["PWCHAR","lpTimerName","in"],
			])
		
		railgun.add_function('kernel32',  'DeactivateActCtx', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PDWORD","ulCookie","in"],
			])
		
		railgun.add_function('kernel32',  'DebugActiveProcess', 'BOOL',[
			["DWORD","dwProcessId","in"],
			])
		
		railgun.add_function('kernel32',  'DebugActiveProcessStop', 'BOOL',[
			["DWORD","dwProcessId","in"],
			])
		
		railgun.add_function('kernel32',  'DebugBreak', 'VOID',[
			])
		
		railgun.add_function('kernel32',  'DebugBreakProcess', 'BOOL',[
			["DWORD","Process","in"],
			])
		
		railgun.add_function('kernel32',  'DebugSetProcessKillOnExit', 'BOOL',[
			["BOOL","KillOnExit","in"],
			])
		
		railgun.add_function('kernel32',  'DecodePointer', 'PBLOB',[
			["PBLOB","Ptr","in"],
			])
		
		railgun.add_function('kernel32',  'DecodeSystemPointer', 'PBLOB',[
			["PBLOB","Ptr","in"],
			])
		
		railgun.add_function('kernel32',  'DefineDosDeviceA', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PCHAR","lpDeviceName","in"],
			["PCHAR","lpTargetPath","in"],
			])
		
		railgun.add_function('kernel32',  'DefineDosDeviceW', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PWCHAR","lpDeviceName","in"],
			["PWCHAR","lpTargetPath","in"],
			])
		
		railgun.add_function('kernel32',  'DeleteAtom', 'WORD',[
			["WORD","nAtom","in"],
			])
		
		railgun.add_function('kernel32',  'DeleteCriticalSection', 'VOID',[
			["PBLOB","lpCriticalSection","inout"],
			])
		
		railgun.add_function('kernel32',  'DeleteFiber', 'VOID',[
			["PBLOB","lpFiber","in"],
			])
		
		railgun.add_function('kernel32',  'DeleteFileA', 'BOOL',[
			["PCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'DeleteFileW', 'BOOL',[
			["PWCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'DeleteTimerQueue', 'BOOL',[
			["DWORD","TimerQueue","in"],
			])
		
		railgun.add_function('kernel32',  'DeleteTimerQueueEx', 'BOOL',[
			["DWORD","TimerQueue","in"],
			["DWORD","CompletionEvent","in"],
			])
		
		railgun.add_function('kernel32',  'DeleteTimerQueueTimer', 'BOOL',[
			["DWORD","TimerQueue","in"],
			["DWORD","Timer","in"],
			["DWORD","CompletionEvent","in"],
			])
		
		railgun.add_function('kernel32',  'DeleteVolumeMountPointA', 'BOOL',[
			["PCHAR","lpszVolumeMountPoint","in"],
			])
		
		railgun.add_function('kernel32',  'DeleteVolumeMountPointW', 'BOOL',[
			["PWCHAR","lpszVolumeMountPoint","in"],
			])
		
		railgun.add_function('kernel32',  'DeviceIoControl', 'BOOL',[
			["DWORD","hDevice","in"],
			["DWORD","dwIoControlCode","in"],
			["PBLOB","lpInBuffer","in"],
			["DWORD","nInBufferSize","in"],
			["PBLOB","lpOutBuffer","out"],
			["DWORD","nOutBufferSize","in"],
			["PDWORD","lpBytesReturned","out"],
			["PBLOB","lpOverlapped","inout"],
			])
		
		railgun.add_function('kernel32',  'DisableThreadLibraryCalls', 'BOOL',[
			["DWORD","hLibModule","in"],
			])
		
		railgun.add_function('kernel32',  'DisconnectNamedPipe', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			])
		
		railgun.add_function('kernel32',  'DnsHostnameToComputerNameA', 'BOOL',[
			["PCHAR","Hostname","in"],
			["PCHAR","ComputerName","out"],
			["PDWORD","nSize","inout"],
			])
		
		railgun.add_function('kernel32',  'DnsHostnameToComputerNameW', 'BOOL',[
			["PWCHAR","Hostname","in"],
			["PWCHAR","ComputerName","out"],
			["PDWORD","nSize","inout"],
			])
		
		railgun.add_function('kernel32',  'DosDateTimeToFileTime', 'BOOL',[
			["WORD","wFatDate","in"],
			["WORD","wFatTime","in"],
			["PBLOB","lpFileTime","out"],
			])
		
		railgun.add_function('kernel32',  'DuplicateHandle', 'BOOL',[
			["DWORD","hSourceProcessHandle","in"],
			["DWORD","hSourceHandle","in"],
			["DWORD","hTargetProcessHandle","in"],
			["PDWORD","lpTargetHandle","out"],
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["DWORD","dwOptions","in"],
			])
		
		railgun.add_function('kernel32',  'EncodePointer', 'PBLOB',[
			["PBLOB","Ptr","in"],
			])
		
		railgun.add_function('kernel32',  'EncodeSystemPointer', 'PBLOB',[
			["PBLOB","Ptr","in"],
			])
		
		railgun.add_function('kernel32',  'EndUpdateResourceA', 'BOOL',[
			["DWORD","hUpdate","in"],
			["BOOL","fDiscard","in"],
			])
		
		railgun.add_function('kernel32',  'EndUpdateResourceW', 'BOOL',[
			["DWORD","hUpdate","in"],
			["BOOL","fDiscard","in"],
			])
		
		railgun.add_function('kernel32',  'EnterCriticalSection', 'VOID',[
			["PBLOB","lpCriticalSection","inout"],
			])
		
		railgun.add_function('kernel32',  'EnumResourceLanguagesA', 'BOOL',[
			["DWORD","hModule","in"],
			["PCHAR","lpType","in"],
			["PCHAR","lpName","in"],
			["PBLOB","lpEnumFunc","in"],
			["PBLOB","lParam","in"],
			])
		
		railgun.add_function('kernel32',  'EnumResourceLanguagesW', 'BOOL',[
			["DWORD","hModule","in"],
			["PWCHAR","lpType","in"],
			["PWCHAR","lpName","in"],
			["PBLOB","lpEnumFunc","in"],
			["PBLOB","lParam","in"],
			])
		
		railgun.add_function('kernel32',  'EnumResourceNamesA', 'BOOL',[
			["DWORD","hModule","in"],
			["PCHAR","lpType","in"],
			["PBLOB","lpEnumFunc","in"],
			["PBLOB","lParam","in"],
			])
		
		railgun.add_function('kernel32',  'EnumResourceNamesW', 'BOOL',[
			["DWORD","hModule","in"],
			["PWCHAR","lpType","in"],
			["PBLOB","lpEnumFunc","in"],
			["PBLOB","lParam","in"],
			])
		
		railgun.add_function('kernel32',  'EnumResourceTypesA', 'BOOL',[
			["DWORD","hModule","in"],
			["PBLOB","lpEnumFunc","in"],
			["PBLOB","lParam","in"],
			])
		
		railgun.add_function('kernel32',  'EnumResourceTypesW', 'BOOL',[
			["DWORD","hModule","in"],
			["PBLOB","lpEnumFunc","in"],
			["PBLOB","lParam","in"],
			])
		
		railgun.add_function('kernel32',  'EnumSystemFirmwareTables', 'DWORD',[
			["DWORD","FirmwareTableProviderSignature","in"],
			["PBLOB","pFirmwareTableEnumBuffer","out"],
			["DWORD","BufferSize","in"],
			])
		
		railgun.add_function('kernel32',  'EraseTape', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwEraseType","in"],
			["BOOL","bImmediate","in"],
			])
		
		railgun.add_function('kernel32',  'EscapeCommFunction', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwFunc","in"],
			])
		
		railgun.add_function('kernel32',  'ExitProcess', 'VOID',[
			["DWORD","uExitCode","in"],
			])
		
		railgun.add_function('kernel32',  'ExitThread', 'VOID',[
			["DWORD","dwExitCode","in"],
			])
		
		railgun.add_function('kernel32',  'ExpandEnvironmentStringsA', 'DWORD',[
			["PCHAR","lpSrc","in"],
			["PCHAR","lpDst","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'ExpandEnvironmentStringsW', 'DWORD',[
			["PWCHAR","lpSrc","in"],
			["PWCHAR","lpDst","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'FatalAppExitA', 'VOID',[
			["DWORD","uAction","in"],
			["PCHAR","lpMessageText","in"],
			])
		
		railgun.add_function('kernel32',  'FatalAppExitW', 'VOID',[
			["DWORD","uAction","in"],
			["PWCHAR","lpMessageText","in"],
			])
		
		railgun.add_function('kernel32',  'FatalExit', 'VOID',[
			["DWORD","ExitCode","in"],
			])
		
		railgun.add_function('kernel32',  'FileTimeToDosDateTime', 'BOOL',[
			["PBLOB","lpFileTime","in"],
			["PBLOB","lpFatDate","out"],
			["PBLOB","lpFatTime","out"],
			])
		
		railgun.add_function('kernel32',  'FileTimeToLocalFileTime', 'BOOL',[
			["PBLOB","lpFileTime","in"],
			["PBLOB","lpLocalFileTime","out"],
			])
		
		railgun.add_function('kernel32',  'FileTimeToSystemTime', 'BOOL',[
			["PBLOB","lpFileTime","in"],
			["PBLOB","lpSystemTime","out"],
			])
		
		railgun.add_function('kernel32',  'FindActCtxSectionGuid', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PBLOB","lpExtensionGuid","inout"],
			["DWORD","ulSectionId","in"],
			["PBLOB","lpGuidToFind","in"],
			["PBLOB","ReturnedData","out"],
			])
		
		railgun.add_function('kernel32',  'FindActCtxSectionStringA', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PBLOB","lpExtensionGuid","inout"],
			["DWORD","ulSectionId","in"],
			["PCHAR","lpStringToFind","in"],
			["PBLOB","ReturnedData","out"],
			])
		
		railgun.add_function('kernel32',  'FindActCtxSectionStringW', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PBLOB","lpExtensionGuid","inout"],
			["DWORD","ulSectionId","in"],
			["PWCHAR","lpStringToFind","in"],
			["PBLOB","ReturnedData","out"],
			])
		
		railgun.add_function('kernel32',  'FindAtomA', 'WORD',[
			["PCHAR","lpString","in"],
			])
		
		railgun.add_function('kernel32',  'FindAtomW', 'WORD',[
			["PWCHAR","lpString","in"],
			])
		
		railgun.add_function('kernel32',  'FindClose', 'BOOL',[
			["DWORD","hFindFile","inout"],
			])
		
		railgun.add_function('kernel32',  'FindCloseChangeNotification', 'BOOL',[
			["DWORD","hChangeHandle","in"],
			])
		
		railgun.add_function('kernel32',  'FindFirstChangeNotificationA', 'DWORD',[
			["PCHAR","lpPathName","in"],
			["BOOL","bWatchSubtree","in"],
			["DWORD","dwNotifyFilter","in"],
			])
		
		railgun.add_function('kernel32',  'FindFirstChangeNotificationW', 'DWORD',[
			["PWCHAR","lpPathName","in"],
			["BOOL","bWatchSubtree","in"],
			["DWORD","dwNotifyFilter","in"],
			])
		
		railgun.add_function('kernel32',  'FindFirstFileA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			["PBLOB","lpFindFileData","out"],
			])
		
		railgun.add_function('kernel32',  'FindFirstFileExA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			["PBLOB","fInfoLevelId","in"],
			["PBLOB","lpFindFileData","out"],
			["PBLOB","fSearchOp","in"],
			["PBLOB","lpSearchFilter","inout"],
			["DWORD","dwAdditionalFlags","in"],
			])
		
		railgun.add_function('kernel32',  'FindFirstFileExW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			["PBLOB","fInfoLevelId","in"],
			["PBLOB","lpFindFileData","out"],
			["PBLOB","fSearchOp","in"],
			["PBLOB","lpSearchFilter","inout"],
			["DWORD","dwAdditionalFlags","in"],
			])
		
		railgun.add_function('kernel32',  'FindFirstFileW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			["PBLOB","lpFindFileData","out"],
			])
		
		railgun.add_function('kernel32',  'FindFirstStreamW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			["PBLOB","InfoLevel","in"],
			["PBLOB","lpFindStreamData","out"],
			["DWORD","dwFlags","inout"],
			])
		
		railgun.add_function('kernel32',  'FindFirstVolumeA', 'DWORD',[
			["PCHAR","lpszVolumeName","out"],
			["DWORD","cchBufferLength","in"],
			])
		
		railgun.add_function('kernel32',  'FindFirstVolumeMountPointA', 'DWORD',[
			["PCHAR","lpszRootPathName","in"],
			["PCHAR","lpszVolumeMountPoint","out"],
			["DWORD","cchBufferLength","in"],
			])
		
		railgun.add_function('kernel32',  'FindFirstVolumeMountPointW', 'DWORD',[
			["PWCHAR","lpszRootPathName","in"],
			["PWCHAR","lpszVolumeMountPoint","out"],
			["DWORD","cchBufferLength","in"],
			])
		
		railgun.add_function('kernel32',  'FindFirstVolumeW', 'DWORD',[
			["PWCHAR","lpszVolumeName","out"],
			["DWORD","cchBufferLength","in"],
			])
		
		railgun.add_function('kernel32',  'FindNextChangeNotification', 'BOOL',[
			["DWORD","hChangeHandle","in"],
			])
		
		railgun.add_function('kernel32',  'FindNextFileA', 'BOOL',[
			["DWORD","hFindFile","in"],
			["PBLOB","lpFindFileData","out"],
			])
		
		railgun.add_function('kernel32',  'FindNextFileW', 'BOOL',[
			["DWORD","hFindFile","in"],
			["PBLOB","lpFindFileData","out"],
			])
		
		railgun.add_function('kernel32',  'FindNextStreamW', 'BOOL',[
			["DWORD","hFindStream","in"],
			["PBLOB","lpFindStreamData","out"],
			])
		
		railgun.add_function('kernel32',  'FindNextVolumeA', 'BOOL',[
			["DWORD","hFindVolume","inout"],
			["PCHAR","lpszVolumeName","out"],
			["DWORD","cchBufferLength","in"],
			])
		
		railgun.add_function('kernel32',  'FindNextVolumeMountPointA', 'BOOL',[
			["DWORD","hFindVolumeMountPoint","in"],
			["PCHAR","lpszVolumeMountPoint","out"],
			["DWORD","cchBufferLength","in"],
			])
		
		railgun.add_function('kernel32',  'FindNextVolumeMountPointW', 'BOOL',[
			["DWORD","hFindVolumeMountPoint","in"],
			["PWCHAR","lpszVolumeMountPoint","out"],
			["DWORD","cchBufferLength","in"],
			])
		
		railgun.add_function('kernel32',  'FindNextVolumeW', 'BOOL',[
			["DWORD","hFindVolume","inout"],
			["PWCHAR","lpszVolumeName","out"],
			["DWORD","cchBufferLength","in"],
			])
		
		railgun.add_function('kernel32',  'FindResourceA', 'DWORD',[
			["DWORD","hModule","in"],
			["PCHAR","lpName","in"],
			["PCHAR","lpType","in"],
			])
		
		railgun.add_function('kernel32',  'FindResourceExA', 'DWORD',[
			["DWORD","hModule","in"],
			["PCHAR","lpType","in"],
			["PCHAR","lpName","in"],
			["WORD","wLanguage","in"],
			])
		
		railgun.add_function('kernel32',  'FindResourceExW', 'DWORD',[
			["DWORD","hModule","in"],
			["PWCHAR","lpType","in"],
			["PWCHAR","lpName","in"],
			["WORD","wLanguage","in"],
			])
		
		railgun.add_function('kernel32',  'FindResourceW', 'DWORD',[
			["DWORD","hModule","in"],
			["PWCHAR","lpName","in"],
			["PWCHAR","lpType","in"],
			])
		
		railgun.add_function('kernel32',  'FindVolumeClose', 'BOOL',[
			["DWORD","hFindVolume","in"],
			])
		
		railgun.add_function('kernel32',  'FindVolumeMountPointClose', 'BOOL',[
			["DWORD","hFindVolumeMountPoint","in"],
			])
		
		railgun.add_function('kernel32',  'FlsAlloc', 'DWORD',[
			["PBLOB","lpCallback","in"],
			])
		
		railgun.add_function('kernel32',  'FlsFree', 'BOOL',[
			["DWORD","dwFlsIndex","in"],
			])
		
		railgun.add_function('kernel32',  'FlsGetValue', 'PBLOB',[
			["DWORD","dwFlsIndex","in"],
			])
		
		railgun.add_function('kernel32',  'FlsSetValue', 'BOOL',[
			["DWORD","dwFlsIndex","in"],
			["PBLOB","lpFlsData","in"],
			])
		
		railgun.add_function('kernel32',  'FlushFileBuffers', 'BOOL',[
			["DWORD","hFile","in"],
			])
		
		railgun.add_function('kernel32',  'FlushInstructionCache', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpBaseAddress","in"],
			["DWORD","dwSize","in"],
			])
		
		railgun.add_function('kernel32',  'FlushViewOfFile', 'BOOL',[
			["PBLOB","lpBaseAddress","in"],
			["DWORD","dwNumberOfBytesToFlush","in"],
			])
		
		railgun.add_function('kernel32',  'FreeEnvironmentStringsA', 'BOOL',[
			["PBLOB","param0","in"],
			])
		
		railgun.add_function('kernel32',  'FreeEnvironmentStringsW', 'BOOL',[
			["PBLOB","param0","in"],
			])
		
		railgun.add_function('kernel32',  'FreeLibrary', 'BOOL',[
			["DWORD","hLibModule","in"],
			])
		
		railgun.add_function('kernel32',  'FreeLibraryAndExitThread', 'VOID',[
			["DWORD","hLibModule","in"],
			["DWORD","dwExitCode","in"],
			])
		
		railgun.add_function('kernel32',  'FreeResource', 'BOOL',[
			["DWORD","hResData","in"],
			])
		
		railgun.add_function('kernel32',  'FreeUserPhysicalPages', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","NumberOfPages","inout"],
			["PBLOB","PageArray","in"],
			])
		
		railgun.add_function('kernel32',  'GetAtomNameA', 'DWORD',[
			["WORD","nAtom","in"],
			["PCHAR","lpBuffer","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetAtomNameW', 'DWORD',[
			["WORD","nAtom","in"],
			["PWCHAR","lpBuffer","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetBinaryTypeA', 'BOOL',[
			["PCHAR","lpApplicationName","in"],
			["PDWORD","lpBinaryType","out"],
			])
		
		railgun.add_function('kernel32',  'GetBinaryTypeW', 'BOOL',[
			["PWCHAR","lpApplicationName","in"],
			["PDWORD","lpBinaryType","out"],
			])
		
		railgun.add_function('kernel32',  'GetCommConfig', 'BOOL',[
			["DWORD","hCommDev","in"],
			["PBLOB","lpCC","out"],
			["PDWORD","lpdwSize","inout"],
			])
		
		railgun.add_function('kernel32',  'GetCommMask', 'BOOL',[
			["DWORD","hFile","in"],
			["PDWORD","lpEvtMask","out"],
			])
		
		railgun.add_function('kernel32',  'GetCommModemStatus', 'BOOL',[
			["DWORD","hFile","in"],
			["PDWORD","lpModemStat","out"],
			])
		
		railgun.add_function('kernel32',  'GetCommProperties', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpCommProp","out"],
			])
		
		railgun.add_function('kernel32',  'GetCommState', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpDCB","out"],
			])
		
		railgun.add_function('kernel32',  'GetCommTimeouts', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpCommTimeouts","out"],
			])
		
		railgun.add_function('kernel32',  'GetCommandLineA', 'PCHAR',[
			])
		
		railgun.add_function('kernel32',  'GetCommandLineW', 'PWCHAR',[
			])
		
		railgun.add_function('kernel32',  'GetCompressedFileSizeA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			["PDWORD","lpFileSizeHigh","out"],
			])
		
		railgun.add_function('kernel32',  'GetCompressedFileSizeW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			["PDWORD","lpFileSizeHigh","out"],
			])
		
		railgun.add_function('kernel32',  'GetComputerNameA', 'BOOL',[
			["PCHAR","lpBuffer","out"],
			["PDWORD","nSize","inout"],
			])
		
		railgun.add_function('kernel32',  'GetComputerNameExA', 'BOOL',[
			["DWORD","NameType","in"],
			["PCHAR","lpBuffer","out"],
			["PDWORD","nSize","inout"],
			])
		
		railgun.add_function('kernel32',  'GetComputerNameExW', 'BOOL',[
			["DWORD","NameType","in"],
			["PWCHAR","lpBuffer","out"],
			["PDWORD","nSize","inout"],
			])
		
		railgun.add_function('kernel32',  'GetComputerNameW', 'BOOL',[
			["PWCHAR","lpBuffer","out"],
			["PDWORD","nSize","inout"],
			])
		
		railgun.add_function('kernel32',  'GetCurrentActCtx', 'BOOL',[
			["PDWORD","lphActCtx","out"],
			])
		
		railgun.add_function('kernel32',  'GetCurrentDirectoryA', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PCHAR","lpBuffer","out"],
			])
		
		railgun.add_function('kernel32',  'GetCurrentDirectoryW', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PWCHAR","lpBuffer","out"],
			])
		
		railgun.add_function('kernel32',  'GetCurrentProcess', 'DWORD',[
			])
		
		railgun.add_function('kernel32',  'GetCurrentProcessId', 'DWORD',[
			])
		
		railgun.add_function('kernel32',  'GetCurrentProcessorNumber', 'DWORD',[
			])
		
		railgun.add_function('kernel32',  'GetCurrentThread', 'DWORD',[
			])
		
		railgun.add_function('kernel32',  'GetCurrentThreadId', 'DWORD',[
			])
		
		railgun.add_function('kernel32',  'GetDefaultCommConfigA', 'BOOL',[
			["PCHAR","lpszName","in"],
			["PBLOB","lpCC","out"],
			["PDWORD","lpdwSize","inout"],
			])
		
		railgun.add_function('kernel32',  'GetDefaultCommConfigW', 'BOOL',[
			["PWCHAR","lpszName","in"],
			["PBLOB","lpCC","out"],
			["PDWORD","lpdwSize","inout"],
			])
		
		railgun.add_function('kernel32',  'GetDevicePowerState', 'BOOL',[
			["DWORD","hDevice","in"],
			["PBLOB","pfOn","out"],
			])
		
		railgun.add_function('kernel32',  'GetDiskFreeSpaceA', 'BOOL',[
			["PCHAR","lpRootPathName","in"],
			["PDWORD","lpSectorsPerCluster","out"],
			["PDWORD","lpBytesPerSector","out"],
			["PDWORD","lpNumberOfFreeClusters","out"],
			["PDWORD","lpTotalNumberOfClusters","out"],
			])
		
		railgun.add_function('kernel32',  'GetDiskFreeSpaceExA', 'BOOL',[
			["PCHAR","lpDirectoryName","in"],
			["PBLOB","lpFreeBytesAvailableToCaller","out"],
			["PBLOB","lpTotalNumberOfBytes","out"],
			["PBLOB","lpTotalNumberOfFreeBytes","out"],
			])
		
		railgun.add_function('kernel32',  'GetDiskFreeSpaceExW', 'BOOL',[
			["PWCHAR","lpDirectoryName","in"],
			["PBLOB","lpFreeBytesAvailableToCaller","out"],
			["PBLOB","lpTotalNumberOfBytes","out"],
			["PBLOB","lpTotalNumberOfFreeBytes","out"],
			])
		
		railgun.add_function('kernel32',  'GetDiskFreeSpaceW', 'BOOL',[
			["PWCHAR","lpRootPathName","in"],
			["PDWORD","lpSectorsPerCluster","out"],
			["PDWORD","lpBytesPerSector","out"],
			["PDWORD","lpNumberOfFreeClusters","out"],
			["PDWORD","lpTotalNumberOfClusters","out"],
			])
		
		railgun.add_function('kernel32',  'GetDllDirectoryA', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PCHAR","lpBuffer","out"],
			])
		
		railgun.add_function('kernel32',  'GetDllDirectoryW', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PWCHAR","lpBuffer","out"],
			])
		
		railgun.add_function('kernel32',  'GetDriveTypeA', 'DWORD',[
			["PCHAR","lpRootPathName","in"],
			])
		
		railgun.add_function('kernel32',  'GetDriveTypeW', 'DWORD',[
			["PWCHAR","lpRootPathName","in"],
			])
		
		railgun.add_function('kernel32',  'GetEnvironmentStrings', 'PBLOB',[
			])
		
		railgun.add_function('kernel32',  'GetEnvironmentStringsW', 'PBLOB',[
			])
		
		railgun.add_function('kernel32',  'GetEnvironmentVariableA', 'DWORD',[
			["PCHAR","lpName","in"],
			["PCHAR","lpBuffer","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetEnvironmentVariableW', 'DWORD',[
			["PWCHAR","lpName","in"],
			["PWCHAR","lpBuffer","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetExitCodeProcess', 'BOOL',[
			["DWORD","hProcess","in"],
			["PDWORD","lpExitCode","out"],
			])
		
		railgun.add_function('kernel32',  'GetExitCodeThread', 'BOOL',[
			["DWORD","hThread","in"],
			["PDWORD","lpExitCode","out"],
			])
		
		railgun.add_function('kernel32',  'GetFileAttributesA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'GetFileAttributesExA', 'BOOL',[
			["PCHAR","lpFileName","in"],
			["PBLOB","fInfoLevelId","in"],
			["PBLOB","lpFileInformation","out"],
			])
		
		railgun.add_function('kernel32',  'GetFileAttributesExW', 'BOOL',[
			["PWCHAR","lpFileName","in"],
			["PBLOB","fInfoLevelId","in"],
			["PBLOB","lpFileInformation","out"],
			])
		
		railgun.add_function('kernel32',  'GetFileAttributesW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'GetFileInformationByHandle', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpFileInformation","out"],
			])
		
		railgun.add_function('kernel32',  'GetFileSize', 'DWORD',[
			["DWORD","hFile","in"],
			["PDWORD","lpFileSizeHigh","out"],
			])
		
		railgun.add_function('kernel32',  'GetFileSizeEx', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpFileSize","out"],
			])
		
		railgun.add_function('kernel32',  'GetFileTime', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpCreationTime","out"],
			["PBLOB","lpLastAccessTime","out"],
			["PBLOB","lpLastWriteTime","out"],
			])
		
		railgun.add_function('kernel32',  'GetFileType', 'DWORD',[
			["DWORD","hFile","in"],
			])
		
		railgun.add_function('kernel32',  'GetFirmwareEnvironmentVariableA', 'DWORD',[
			["PCHAR","lpName","in"],
			["PCHAR","lpGuid","in"],
			["PBLOB","pBuffer","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetFirmwareEnvironmentVariableW', 'DWORD',[
			["PWCHAR","lpName","in"],
			["PWCHAR","lpGuid","in"],
			["PBLOB","pBuffer","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetFullPathNameA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			["DWORD","nBufferLength","in"],
			["PCHAR","lpBuffer","out"],
			["PBLOB","lpFilePart","out"],
			])
		
		railgun.add_function('kernel32',  'GetFullPathNameW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			["DWORD","nBufferLength","in"],
			["PWCHAR","lpBuffer","out"],
			["PBLOB","lpFilePart","out"],
			])
		
		railgun.add_function('kernel32',  'GetHandleInformation', 'BOOL',[
			["DWORD","hObject","in"],
			["PDWORD","lpdwFlags","out"],
			])
		
		railgun.add_function('kernel32',  'GetLargePageMinimum', 'DWORD',[
			])
		
		railgun.add_function('kernel32',  'GetLastError', 'DWORD',[
			])
		
		railgun.add_function('kernel32',  'GetLocalTime', 'VOID',[
			["PBLOB","lpSystemTime","out"],
			])
		
		railgun.add_function('kernel32',  'GetLogicalDriveStringsA', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PCHAR","lpBuffer","out"],
			])
		
		railgun.add_function('kernel32',  'GetLogicalDriveStringsW', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PWCHAR","lpBuffer","out"],
			])
		
		railgun.add_function('kernel32',  'GetLogicalDrives', 'DWORD',[
			])
		
		railgun.add_function('kernel32',  'GetLogicalProcessorInformation', 'BOOL',[
			["PBLOB","Buffer","out"],
			["PDWORD","ReturnedLength","inout"],
			])
		
		railgun.add_function('kernel32',  'GetLongPathNameA', 'DWORD',[
			["PCHAR","lpszShortPath","in"],
			["PCHAR","lpszLongPath","out"],
			["DWORD","cchBuffer","in"],
			])
		
		railgun.add_function('kernel32',  'GetLongPathNameW', 'DWORD',[
			["PWCHAR","lpszShortPath","in"],
			["PWCHAR","lpszLongPath","out"],
			["DWORD","cchBuffer","in"],
			])
		
		railgun.add_function('kernel32',  'GetMailslotInfo', 'BOOL',[
			["DWORD","hMailslot","in"],
			["PDWORD","lpMaxMessageSize","out"],
			["PDWORD","lpNextSize","out"],
			["PDWORD","lpMessageCount","out"],
			["PDWORD","lpReadTimeout","out"],
			])
		
		railgun.add_function('kernel32',  'GetModuleFileNameA', 'DWORD',[
			["DWORD","hModule","in"],
			["PBLOB","lpFilename","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetModuleFileNameW', 'DWORD',[
			["DWORD","hModule","in"],
			["PBLOB","lpFilename","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetModuleHandleA', 'DWORD',[
			["PCHAR","lpModuleName","in"],
			])
		
		railgun.add_function('kernel32',  'GetModuleHandleExA', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PCHAR","lpModuleName","in"],
			["PDWORD","phModule","out"],
			])
		
		railgun.add_function('kernel32',  'GetModuleHandleExW', 'BOOL',[
			["DWORD","dwFlags","in"],
			["PWCHAR","lpModuleName","in"],
			["PDWORD","phModule","out"],
			])
		
		railgun.add_function('kernel32',  'GetModuleHandleW', 'DWORD',[
			["PWCHAR","lpModuleName","in"],
			])
		
		railgun.add_function('kernel32',  'GetNamedPipeHandleStateA', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			["PDWORD","lpState","out"],
			["PDWORD","lpCurInstances","out"],
			["PDWORD","lpMaxCollectionCount","out"],
			["PDWORD","lpCollectDataTimeout","out"],
			["PCHAR","lpUserName","out"],
			["DWORD","nMaxUserNameSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetNamedPipeHandleStateW', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			["PDWORD","lpState","out"],
			["PDWORD","lpCurInstances","out"],
			["PDWORD","lpMaxCollectionCount","out"],
			["PDWORD","lpCollectDataTimeout","out"],
			["PWCHAR","lpUserName","out"],
			["DWORD","nMaxUserNameSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetNamedPipeInfo', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			["PDWORD","lpFlags","out"],
			["PDWORD","lpOutBufferSize","out"],
			["PDWORD","lpInBufferSize","out"],
			["PDWORD","lpMaxInstances","out"],
			])
		
		railgun.add_function('kernel32',  'GetNativeSystemInfo', 'VOID',[
			["PBLOB","lpSystemInfo","out"],
			])
		
		railgun.add_function('kernel32',  'GetNumaAvailableMemoryNode', 'BOOL',[
			["BYTE","Node","in"],
			["PBLOB","AvailableBytes","out"],
			])
		
		railgun.add_function('kernel32',  'GetNumaHighestNodeNumber', 'BOOL',[
			["PDWORD","HighestNodeNumber","out"],
			])
		
		railgun.add_function('kernel32',  'GetNumaNodeProcessorMask', 'BOOL',[
			["BYTE","Node","in"],
			["PBLOB","ProcessorMask","out"],
			])
		
		railgun.add_function('kernel32',  'GetNumaProcessorNode', 'BOOL',[
			["BYTE","Processor","in"],
			["PBLOB","NodeNumber","out"],
			])
		
		railgun.add_function('kernel32',  'GetOverlappedResult', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpOverlapped","in"],
			["PDWORD","lpNumberOfBytesTransferred","out"],
			["BOOL","bWait","in"],
			])
		
		railgun.add_function('kernel32',  'GetPriorityClass', 'DWORD',[
			["DWORD","hProcess","in"],
			])
		
		railgun.add_function('kernel32',  'GetPrivateProfileIntA', 'DWORD',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpKeyName","in"],
			["DWORD","nDefault","in"],
			["PCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'GetPrivateProfileIntW', 'DWORD',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpKeyName","in"],
			["DWORD","nDefault","in"],
			["PWCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'GetPrivateProfileSectionA', 'DWORD',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			["PCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'GetPrivateProfileSectionNamesA', 'DWORD',[
			["PCHAR","lpszReturnBuffer","out"],
			["DWORD","nSize","in"],
			["PCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'GetPrivateProfileSectionNamesW', 'DWORD',[
			["PWCHAR","lpszReturnBuffer","out"],
			["DWORD","nSize","in"],
			["PWCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'GetPrivateProfileSectionW', 'DWORD',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			["PWCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'GetPrivateProfileStringA', 'DWORD',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpKeyName","in"],
			["PCHAR","lpDefault","in"],
			["PCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			["PCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'GetPrivateProfileStringW', 'DWORD',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpKeyName","in"],
			["PWCHAR","lpDefault","in"],
			["PWCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			["PWCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'GetPrivateProfileStructA', 'BOOL',[
			["PCHAR","lpszSection","in"],
			["PCHAR","lpszKey","in"],
			["PBLOB","lpStruct","out"],
			["DWORD","uSizeStruct","in"],
			["PCHAR","szFile","in"],
			])
		
		railgun.add_function('kernel32',  'GetPrivateProfileStructW', 'BOOL',[
			["PWCHAR","lpszSection","in"],
			["PWCHAR","lpszKey","in"],
			["PBLOB","lpStruct","out"],
			["DWORD","uSizeStruct","in"],
			["PWCHAR","szFile","in"],
			])
		
		railgun.add_function('kernel32',  'GetProcAddress', 'PBLOB',[
			["DWORD","hModule","in"],
			["PCHAR","lpProcName","in"],
			])
		
		railgun.add_function('kernel32',  'GetProcessAffinityMask', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpProcessAffinityMask","out"],
			["PBLOB","lpSystemAffinityMask","out"],
			])
		
		railgun.add_function('kernel32',  'GetProcessHandleCount', 'BOOL',[
			["DWORD","hProcess","in"],
			["PDWORD","pdwHandleCount","out"],
			])
		
		railgun.add_function('kernel32',  'GetProcessHeap', 'DWORD',[
			])
		
		railgun.add_function('kernel32',  'GetProcessHeaps', 'DWORD',[
			["DWORD","NumberOfHeaps","in"],
			["PDWORD","ProcessHeaps","out"],
			])
		
		railgun.add_function('kernel32',  'GetProcessId', 'DWORD',[
			["DWORD","Process","in"],
			])
		
		railgun.add_function('kernel32',  'GetProcessIdOfThread', 'DWORD',[
			["DWORD","Thread","in"],
			])
		
		railgun.add_function('kernel32',  'GetProcessIoCounters', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpIoCounters","out"],
			])
		
		railgun.add_function('kernel32',  'GetProcessPriorityBoost', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","pDisablePriorityBoost","out"],
			])
		
		railgun.add_function('kernel32',  'GetProcessShutdownParameters', 'BOOL',[
			["PDWORD","lpdwLevel","out"],
			["PDWORD","lpdwFlags","out"],
			])
		
		railgun.add_function('kernel32',  'GetProcessTimes', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpCreationTime","out"],
			["PBLOB","lpExitTime","out"],
			["PBLOB","lpKernelTime","out"],
			["PBLOB","lpUserTime","out"],
			])
		
		railgun.add_function('kernel32',  'GetProcessVersion', 'DWORD',[
			["DWORD","ProcessId","in"],
			])
		
		railgun.add_function('kernel32',  'GetProcessWorkingSetSize', 'BOOL',[
			["DWORD","hProcess","in"],
			["PDWORD","lpMinimumWorkingSetSize","out"],
			["PDWORD","lpMaximumWorkingSetSize","out"],
			])
		
		railgun.add_function('kernel32',  'GetProcessWorkingSetSizeEx', 'BOOL',[
			["DWORD","hProcess","in"],
			["PDWORD","lpMinimumWorkingSetSize","out"],
			["PDWORD","lpMaximumWorkingSetSize","out"],
			["PDWORD","Flags","out"],
			])
		
		railgun.add_function('kernel32',  'GetProfileIntA', 'DWORD',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpKeyName","in"],
			["DWORD","nDefault","in"],
			])
		
		railgun.add_function('kernel32',  'GetProfileIntW', 'DWORD',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpKeyName","in"],
			["DWORD","nDefault","in"],
			])
		
		railgun.add_function('kernel32',  'GetProfileSectionA', 'DWORD',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetProfileSectionW', 'DWORD',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetProfileStringA', 'DWORD',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpKeyName","in"],
			["PCHAR","lpDefault","in"],
			["PCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetProfileStringW', 'DWORD',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpKeyName","in"],
			["PWCHAR","lpDefault","in"],
			["PWCHAR","lpReturnedString","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetQueuedCompletionStatus', 'BOOL',[
			["DWORD","CompletionPort","in"],
			["PDWORD","lpNumberOfBytesTransferred","out"],
			["PBLOB","lpCompletionKey","out"],
			["PBLOB","lpOverlapped","out"],
			["DWORD","dwMilliseconds","in"],
			])
		
		railgun.add_function('kernel32',  'GetShortPathNameA', 'DWORD',[
			["PCHAR","lpszLongPath","in"],
			["PCHAR","lpszShortPath","out"],
			["DWORD","cchBuffer","in"],
			])
		
		railgun.add_function('kernel32',  'GetShortPathNameW', 'DWORD',[
			["PWCHAR","lpszLongPath","in"],
			["PWCHAR","lpszShortPath","out"],
			["DWORD","cchBuffer","in"],
			])
		
		railgun.add_function('kernel32',  'GetStartupInfoA', 'VOID',[
			["PBLOB","lpStartupInfo","out"],
			])
		
		railgun.add_function('kernel32',  'GetStartupInfoW', 'VOID',[
			["PBLOB","lpStartupInfo","out"],
			])
		
		railgun.add_function('kernel32',  'GetStdHandle', 'DWORD',[
			["DWORD","nStdHandle","in"],
			])
		
		railgun.add_function('kernel32',  'GetSystemDirectoryA', 'DWORD',[
			["PCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetSystemDirectoryW', 'DWORD',[
			["PWCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetSystemFileCacheSize', 'BOOL',[
			["PDWORD","lpMinimumFileCacheSize","out"],
			["PDWORD","lpMaximumFileCacheSize","out"],
			["PDWORD","lpFlags","out"],
			])
		
		railgun.add_function('kernel32',  'GetSystemFirmwareTable', 'DWORD',[
			["DWORD","FirmwareTableProviderSignature","in"],
			["DWORD","FirmwareTableID","in"],
			["PBLOB","pFirmwareTableBuffer","out"],
			["DWORD","BufferSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetSystemInfo', 'VOID',[
			["PBLOB","lpSystemInfo","out"],
			])
		
		railgun.add_function('kernel32',  'GetSystemPowerStatus', 'BOOL',[
			["PBLOB","lpSystemPowerStatus","out"],
			])
		
		railgun.add_function('kernel32',  'GetSystemRegistryQuota', 'BOOL',[
			["PDWORD","pdwQuotaAllowed","out"],
			["PDWORD","pdwQuotaUsed","out"],
			])
		
		railgun.add_function('kernel32',  'GetSystemTime', 'VOID',[
			["PBLOB","lpSystemTime","out"],
			])
		
		railgun.add_function('kernel32',  'GetSystemTimeAdjustment', 'BOOL',[
			["PDWORD","lpTimeAdjustment","out"],
			["PDWORD","lpTimeIncrement","out"],
			["PBLOB","lpTimeAdjustmentDisabled","out"],
			])
		
		railgun.add_function('kernel32',  'GetSystemTimeAsFileTime', 'VOID',[
			["PBLOB","lpSystemTimeAsFileTime","out"],
			])
		
		railgun.add_function('kernel32',  'GetSystemTimes', 'BOOL',[
			["PBLOB","lpIdleTime","out"],
			["PBLOB","lpKernelTime","out"],
			["PBLOB","lpUserTime","out"],
			])
		
		railgun.add_function('kernel32',  'GetSystemWindowsDirectoryA', 'DWORD',[
			["PCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetSystemWindowsDirectoryW', 'DWORD',[
			["PWCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetSystemWow64DirectoryA', 'DWORD',[
			["PCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetSystemWow64DirectoryW', 'DWORD',[
			["PWCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetTapeParameters', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwOperation","in"],
			["PDWORD","lpdwSize","inout"],
			["PBLOB","lpTapeInformation","out"],
			])
		
		railgun.add_function('kernel32',  'GetTapePosition', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwPositionType","in"],
			["PDWORD","lpdwPartition","out"],
			["PDWORD","lpdwOffsetLow","out"],
			["PDWORD","lpdwOffsetHigh","out"],
			])
		
		railgun.add_function('kernel32',  'GetTapeStatus', 'DWORD',[
			["DWORD","hDevice","in"],
			])
		
		railgun.add_function('kernel32',  'GetTempFileNameA', 'DWORD',[
			["PCHAR","lpPathName","in"],
			["PCHAR","lpPrefixString","in"],
			["DWORD","uUnique","in"],
			["PCHAR","lpTempFileName","out"],
			])
		
		railgun.add_function('kernel32',  'GetTempFileNameW', 'DWORD',[
			["PWCHAR","lpPathName","in"],
			["PWCHAR","lpPrefixString","in"],
			["DWORD","uUnique","in"],
			["PWCHAR","lpTempFileName","out"],
			])
		
		railgun.add_function('kernel32',  'GetTempPathA', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PCHAR","lpBuffer","out"],
			])
		
		railgun.add_function('kernel32',  'GetTempPathW', 'DWORD',[
			["DWORD","nBufferLength","in"],
			["PWCHAR","lpBuffer","out"],
			])
		
		railgun.add_function('kernel32',  'GetThreadContext', 'BOOL',[
			["DWORD","hThread","in"],
			["PBLOB","lpContext","inout"],
			])
		
		railgun.add_function('kernel32',  'GetThreadIOPendingFlag', 'BOOL',[
			["DWORD","hThread","in"],
			["PBLOB","lpIOIsPending","out"],
			])
		
		railgun.add_function('kernel32',  'GetThreadId', 'DWORD',[
			["DWORD","Thread","in"],
			])
		
		railgun.add_function('kernel32',  'GetThreadPriority', 'DWORD',[
			["DWORD","hThread","in"],
			])
		
		railgun.add_function('kernel32',  'GetThreadPriorityBoost', 'BOOL',[
			["DWORD","hThread","in"],
			["PBLOB","pDisablePriorityBoost","out"],
			])
		
		railgun.add_function('kernel32',  'GetThreadSelectorEntry', 'BOOL',[
			["DWORD","hThread","in"],
			["DWORD","dwSelector","in"],
			["PBLOB","lpSelectorEntry","out"],
			])
		
		railgun.add_function('kernel32',  'GetThreadTimes', 'BOOL',[
			["DWORD","hThread","in"],
			["PBLOB","lpCreationTime","out"],
			["PBLOB","lpExitTime","out"],
			["PBLOB","lpKernelTime","out"],
			["PBLOB","lpUserTime","out"],
			])
		
		railgun.add_function('kernel32',  'GetTickCount', 'DWORD',[
			])
		
		railgun.add_function('kernel32',  'GetTimeZoneInformation', 'DWORD',[
			["PBLOB","lpTimeZoneInformation","out"],
			])
		
		railgun.add_function('kernel32',  'GetVersion', 'DWORD',[
			])
		
		railgun.add_function('kernel32',  'GetVersionExA', 'BOOL',[
			["PBLOB","lpVersionInformation","inout"],
			])
		
		railgun.add_function('kernel32',  'GetVersionExW', 'BOOL',[
			["PBLOB","lpVersionInformation","inout"],
			])
		
		railgun.add_function('kernel32',  'GetVolumeInformationA', 'BOOL',[
			["PCHAR","lpRootPathName","in"],
			["PCHAR","lpVolumeNameBuffer","out"],
			["DWORD","nVolumeNameSize","in"],
			["PDWORD","lpVolumeSerialNumber","out"],
			["PDWORD","lpMaximumComponentLength","out"],
			["PDWORD","lpFileSystemFlags","out"],
			["PCHAR","lpFileSystemNameBuffer","out"],
			["DWORD","nFileSystemNameSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetVolumeInformationW', 'BOOL',[
			["PWCHAR","lpRootPathName","in"],
			["PWCHAR","lpVolumeNameBuffer","out"],
			["DWORD","nVolumeNameSize","in"],
			["PDWORD","lpVolumeSerialNumber","out"],
			["PDWORD","lpMaximumComponentLength","out"],
			["PDWORD","lpFileSystemFlags","out"],
			["PWCHAR","lpFileSystemNameBuffer","out"],
			["DWORD","nFileSystemNameSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetVolumeNameForVolumeMountPointA', 'BOOL',[
			["PCHAR","lpszVolumeMountPoint","in"],
			["PCHAR","lpszVolumeName","out"],
			["DWORD","cchBufferLength","in"],
			])
		
		railgun.add_function('kernel32',  'GetVolumeNameForVolumeMountPointW', 'BOOL',[
			["PWCHAR","lpszVolumeMountPoint","in"],
			["PWCHAR","lpszVolumeName","out"],
			["DWORD","cchBufferLength","in"],
			])
		
		railgun.add_function('kernel32',  'GetVolumePathNameA', 'BOOL',[
			["PCHAR","lpszFileName","in"],
			["PCHAR","lpszVolumePathName","out"],
			["DWORD","cchBufferLength","in"],
			])
		
		railgun.add_function('kernel32',  'GetVolumePathNameW', 'BOOL',[
			["PWCHAR","lpszFileName","in"],
			["PWCHAR","lpszVolumePathName","out"],
			["DWORD","cchBufferLength","in"],
			])
		
		railgun.add_function('kernel32',  'GetVolumePathNamesForVolumeNameA', 'BOOL',[
			["PCHAR","lpszVolumeName","in"],
			["PBLOB","lpszVolumePathNames","out"],
			["DWORD","cchBufferLength","in"],
			["PDWORD","lpcchReturnLength","out"],
			])
		
		railgun.add_function('kernel32',  'GetVolumePathNamesForVolumeNameW', 'BOOL',[
			["PWCHAR","lpszVolumeName","in"],
			["PBLOB","lpszVolumePathNames","out"],
			["DWORD","cchBufferLength","in"],
			["PDWORD","lpcchReturnLength","out"],
			])
		
		railgun.add_function('kernel32',  'GetWindowsDirectoryA', 'DWORD',[
			["PCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetWindowsDirectoryW', 'DWORD',[
			["PWCHAR","lpBuffer","out"],
			["DWORD","uSize","in"],
			])
		
		railgun.add_function('kernel32',  'GetWriteWatch', 'DWORD',[
			["DWORD","dwFlags","in"],
			["PBLOB","lpBaseAddress","in"],
			["DWORD","dwRegionSize","in"],
			["PBLOB","lpAddresses","out"],
			["PBLOB","lpdwCount","inout"],
			["PDWORD","lpdwGranularity","out"],
			])
		
		railgun.add_function('kernel32',  'GlobalAddAtomA', 'WORD',[
			["PCHAR","lpString","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalAddAtomW', 'WORD',[
			["PWCHAR","lpString","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalAlloc', 'DWORD',[
			["DWORD","uFlags","in"],
			["DWORD","dwBytes","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalCompact', 'DWORD',[
			["DWORD","dwMinFree","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalDeleteAtom', 'WORD',[
			["WORD","nAtom","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalFindAtomA', 'WORD',[
			["PCHAR","lpString","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalFindAtomW', 'WORD',[
			["PWCHAR","lpString","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalFix', 'VOID',[
			["DWORD","hMem","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalFlags', 'DWORD',[
			["DWORD","hMem","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalFree', 'DWORD',[
			["DWORD","hMem","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalGetAtomNameA', 'DWORD',[
			["WORD","nAtom","in"],
			["PCHAR","lpBuffer","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalGetAtomNameW', 'DWORD',[
			["WORD","nAtom","in"],
			["PWCHAR","lpBuffer","out"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalHandle', 'DWORD',[
			["PBLOB","pMem","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalLock', 'PBLOB',[
			["DWORD","hMem","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalMemoryStatus', 'VOID',[
			["PBLOB","lpBuffer","out"],
			])
		
		railgun.add_function('kernel32',  'GlobalMemoryStatusEx', 'BOOL',[
			["PBLOB","lpBuffer","out"],
			])
		
		railgun.add_function('kernel32',  'GlobalReAlloc', 'DWORD',[
			["DWORD","hMem","in"],
			["DWORD","dwBytes","in"],
			["DWORD","uFlags","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalSize', 'DWORD',[
			["DWORD","hMem","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalUnWire', 'BOOL',[
			["DWORD","hMem","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalUnfix', 'VOID',[
			["DWORD","hMem","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalUnlock', 'BOOL',[
			["DWORD","hMem","in"],
			])
		
		railgun.add_function('kernel32',  'GlobalWire', 'PBLOB',[
			["DWORD","hMem","in"],
			])
		
		railgun.add_function('kernel32',  'HeapAlloc', 'PBLOB',[
			["DWORD","hHeap","in"],
			["DWORD","dwFlags","in"],
			["DWORD","dwBytes","in"],
			])
		
		railgun.add_function('kernel32',  'HeapCompact', 'DWORD',[
			["DWORD","hHeap","in"],
			["DWORD","dwFlags","in"],
			])
		
		railgun.add_function('kernel32',  'HeapCreate', 'DWORD',[
			["DWORD","flOptions","in"],
			["DWORD","dwInitialSize","in"],
			["DWORD","dwMaximumSize","in"],
			])
		
		railgun.add_function('kernel32',  'HeapDestroy', 'BOOL',[
			["DWORD","hHeap","in"],
			])
		
		railgun.add_function('kernel32',  'HeapFree', 'BOOL',[
			["DWORD","hHeap","inout"],
			["DWORD","dwFlags","in"],
			["PBLOB","lpMem","in"],
			])
		
		railgun.add_function('kernel32',  'HeapLock', 'BOOL',[
			["DWORD","hHeap","in"],
			])
		
		railgun.add_function('kernel32',  'HeapQueryInformation', 'BOOL',[
			["DWORD","HeapHandle","in"],
			["PDWORD","HeapInformationClass","in"],
			["PBLOB","HeapInformation","out"],
			["DWORD","HeapInformationLength","in"],
			["PDWORD","ReturnLength","out"],
			])
		
		railgun.add_function('kernel32',  'HeapReAlloc', 'PBLOB',[
			["DWORD","hHeap","inout"],
			["DWORD","dwFlags","in"],
			["PBLOB","lpMem","in"],
			["DWORD","dwBytes","in"],
			])
		
		railgun.add_function('kernel32',  'HeapSetInformation', 'BOOL',[
			["DWORD","HeapHandle","in"],
			["PDWORD","HeapInformationClass","in"],
			["PBLOB","HeapInformation","in"],
			["DWORD","HeapInformationLength","in"],
			])
		
		railgun.add_function('kernel32',  'HeapSize', 'DWORD',[
			["DWORD","hHeap","in"],
			["DWORD","dwFlags","in"],
			["PBLOB","lpMem","in"],
			])
		
		railgun.add_function('kernel32',  'HeapUnlock', 'BOOL',[
			["DWORD","hHeap","in"],
			])
		
		railgun.add_function('kernel32',  'HeapValidate', 'BOOL',[
			["DWORD","hHeap","in"],
			["DWORD","dwFlags","in"],
			["PBLOB","lpMem","in"],
			])
		
		railgun.add_function('kernel32',  'HeapWalk', 'BOOL',[
			["DWORD","hHeap","in"],
			["PBLOB","lpEntry","inout"],
			])
		
		railgun.add_function('kernel32',  'InitAtomTable', 'BOOL',[
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'InitializeCriticalSection', 'VOID',[
			["PBLOB","lpCriticalSection","out"],
			])
		
		railgun.add_function('kernel32',  'InitializeCriticalSectionAndSpinCount', 'BOOL',[
			["PBLOB","lpCriticalSection","out"],
			["DWORD","dwSpinCount","in"],
			])
		
		railgun.add_function('kernel32',  'InitializeSListHead', 'VOID',[
			["PBLOB","ListHead","inout"],
			])
		
		railgun.add_function('kernel32',  'InterlockedCompareExchange', 'DWORD',[
			["PDWORD","Destination","inout"],
			["DWORD","ExChange","in"],
			["DWORD","Comperand","in"],
			])
		
		railgun.add_function('kernel32',  'InterlockedCompareExchange64', 'PBLOB',[
			["PBLOB","Destination","inout"],
			["PBLOB","ExChange","in"],
			["PBLOB","Comperand","in"],
			])
		
		railgun.add_function('kernel32',  'InterlockedDecrement', 'DWORD',[
			["PDWORD","lpAddend","inout"],
			])
		
		railgun.add_function('kernel32',  'InterlockedExchange', 'DWORD',[
			["PDWORD","Target","inout"],
			["DWORD","Value","in"],
			])
		
		railgun.add_function('kernel32',  'InterlockedExchangeAdd', 'DWORD',[
			["PDWORD","Addend","inout"],
			["DWORD","Value","in"],
			])
		
		railgun.add_function('kernel32',  'InterlockedFlushSList', 'PBLOB',[
			["PBLOB","ListHead","inout"],
			])
		
		railgun.add_function('kernel32',  'InterlockedIncrement', 'DWORD',[
			["PDWORD","lpAddend","inout"],
			])
		
		railgun.add_function('kernel32',  'InterlockedPopEntrySList', 'PBLOB',[
			["PBLOB","ListHead","inout"],
			])
		
		railgun.add_function('kernel32',  'InterlockedPushEntrySList', 'PBLOB',[
			["PBLOB","ListHead","inout"],
			["PBLOB","ListEntry","inout"],
			])
		
		railgun.add_function('kernel32',  'IsBadCodePtr', 'BOOL',[
			["PBLOB","lpfn","in"],
			])
		
		railgun.add_function('kernel32',  'IsBadHugeReadPtr', 'BOOL',[
			["DWORD","ucb","in"],
			])
		
		railgun.add_function('kernel32',  'IsBadHugeWritePtr', 'BOOL',[
			["PBLOB","lp","in"],
			["DWORD","ucb","in"],
			])
		
		railgun.add_function('kernel32',  'IsBadReadPtr', 'BOOL',[
			["DWORD","ucb","in"],
			])
		
		railgun.add_function('kernel32',  'IsBadStringPtrA', 'BOOL',[
			["PCHAR","lpsz","in"],
			["DWORD","ucchMax","in"],
			])
		
		railgun.add_function('kernel32',  'IsBadStringPtrW', 'BOOL',[
			["PWCHAR","lpsz","in"],
			["DWORD","ucchMax","in"],
			])
		
		railgun.add_function('kernel32',  'IsBadWritePtr', 'BOOL',[
			["PBLOB","lp","in"],
			["DWORD","ucb","in"],
			])
		
		railgun.add_function('kernel32',  'IsDebuggerPresent', 'BOOL',[
			])
		
		railgun.add_function('kernel32',  'IsProcessInJob', 'BOOL',[
			["DWORD","ProcessHandle","in"],
			["DWORD","JobHandle","in"],
			["PBLOB","Result","out"],
			])
		
		railgun.add_function('kernel32',  'IsProcessorFeaturePresent', 'BOOL',[
			["DWORD","ProcessorFeature","in"],
			])
		
		railgun.add_function('kernel32',  'IsSystemResumeAutomatic', 'BOOL',[
			])
		
		railgun.add_function('kernel32',  'IsWow64Process', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","Wow64Process","out"],
			])
		
		railgun.add_function('kernel32',  'LeaveCriticalSection', 'VOID',[
			["PBLOB","lpCriticalSection","inout"],
			])
		
		railgun.add_function('kernel32',  'LoadLibraryA', 'DWORD',[
			["PCHAR","lpLibFileName","in"],
			])
		
		railgun.add_function('kernel32',  'LoadLibraryExA', 'DWORD',[
			["PCHAR","lpLibFileName","in"],
			["DWORD","hFile","inout"],
			["DWORD","dwFlags","in"],
			])
		
		railgun.add_function('kernel32',  'LoadLibraryExW', 'DWORD',[
			["PWCHAR","lpLibFileName","in"],
			["DWORD","hFile","inout"],
			["DWORD","dwFlags","in"],
			])
		
		railgun.add_function('kernel32',  'LoadLibraryW', 'DWORD',[
			["PWCHAR","lpLibFileName","in"],
			])
		
		railgun.add_function('kernel32',  'LoadModule', 'DWORD',[
			["PCHAR","lpModuleName","in"],
			["PBLOB","lpParameterBlock","in"],
			])
		
		railgun.add_function('kernel32',  'LoadResource', 'DWORD',[
			["DWORD","hModule","in"],
			["DWORD","hResInfo","in"],
			])
		
		railgun.add_function('kernel32',  'LocalAlloc', 'DWORD',[
			["DWORD","uFlags","in"],
			["DWORD","uBytes","in"],
			])
		
		railgun.add_function('kernel32',  'LocalCompact', 'DWORD',[
			["DWORD","uMinFree","in"],
			])
		
		railgun.add_function('kernel32',  'LocalFileTimeToFileTime', 'BOOL',[
			["PBLOB","lpLocalFileTime","in"],
			["PBLOB","lpFileTime","out"],
			])
		
		railgun.add_function('kernel32',  'LocalFlags', 'DWORD',[
			["DWORD","hMem","in"],
			])
		
		railgun.add_function('kernel32',  'LocalFree', 'DWORD',[
			["DWORD","hMem","in"],
			])
		
		railgun.add_function('kernel32',  'LocalHandle', 'DWORD',[
			["PBLOB","pMem","in"],
			])
		
		railgun.add_function('kernel32',  'LocalLock', 'PBLOB',[
			["DWORD","hMem","in"],
			])
		
		railgun.add_function('kernel32',  'LocalReAlloc', 'DWORD',[
			["DWORD","hMem","in"],
			["DWORD","uBytes","in"],
			["DWORD","uFlags","in"],
			])
		
		railgun.add_function('kernel32',  'LocalShrink', 'DWORD',[
			["DWORD","hMem","in"],
			["DWORD","cbNewSize","in"],
			])
		
		railgun.add_function('kernel32',  'LocalSize', 'DWORD',[
			["DWORD","hMem","in"],
			])
		
		railgun.add_function('kernel32',  'LocalUnlock', 'BOOL',[
			["DWORD","hMem","in"],
			])
		
		railgun.add_function('kernel32',  'LockFile', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwFileOffsetLow","in"],
			["DWORD","dwFileOffsetHigh","in"],
			["DWORD","nNumberOfBytesToLockLow","in"],
			["DWORD","nNumberOfBytesToLockHigh","in"],
			])
		
		railgun.add_function('kernel32',  'LockFileEx', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwFlags","in"],
			["DWORD","dwReserved","inout"],
			["DWORD","nNumberOfBytesToLockLow","in"],
			["DWORD","nNumberOfBytesToLockHigh","in"],
			["PBLOB","lpOverlapped","inout"],
			])
		
		railgun.add_function('kernel32',  'LockResource', 'PBLOB',[
			["DWORD","hResData","in"],
			])
		
		railgun.add_function('kernel32',  'MapUserPhysicalPages', 'BOOL',[
			["PBLOB","VirtualAddress","in"],
			["PDWORD","NumberOfPages","in"],
			["PBLOB","PageArray","in"],
			])
		
		railgun.add_function('kernel32',  'MapUserPhysicalPagesScatter', 'BOOL',[
			["PBLOB","VirtualAddresses","in"],
			["PDWORD","NumberOfPages","in"],
			["PBLOB","PageArray","in"],
			])
		
		railgun.add_function('kernel32',  'MapViewOfFile', 'PBLOB',[
			["DWORD","hFileMappingObject","in"],
			["DWORD","dwDesiredAccess","in"],
			["DWORD","dwFileOffsetHigh","in"],
			["DWORD","dwFileOffsetLow","in"],
			["DWORD","dwNumberOfBytesToMap","in"],
			])
		
		railgun.add_function('kernel32',  'MapViewOfFileEx', 'PBLOB',[
			["DWORD","hFileMappingObject","in"],
			["DWORD","dwDesiredAccess","in"],
			["DWORD","dwFileOffsetHigh","in"],
			["DWORD","dwFileOffsetLow","in"],
			["DWORD","dwNumberOfBytesToMap","in"],
			["PBLOB","lpBaseAddress","in"],
			])
		
		railgun.add_function('kernel32',  'MoveFileA', 'BOOL',[
			["PCHAR","lpExistingFileName","in"],
			["PCHAR","lpNewFileName","in"],
			])
		
		railgun.add_function('kernel32',  'MoveFileExA', 'BOOL',[
			["PCHAR","lpExistingFileName","in"],
			["PCHAR","lpNewFileName","in"],
			["DWORD","dwFlags","in"],
			])
		
		railgun.add_function('kernel32',  'MoveFileExW', 'BOOL',[
			["PWCHAR","lpExistingFileName","in"],
			["PWCHAR","lpNewFileName","in"],
			["DWORD","dwFlags","in"],
			])
		
		railgun.add_function('kernel32',  'MoveFileW', 'BOOL',[
			["PWCHAR","lpExistingFileName","in"],
			["PWCHAR","lpNewFileName","in"],
			])
		
		railgun.add_function('kernel32',  'MoveFileWithProgressA', 'BOOL',[
			["PCHAR","lpExistingFileName","in"],
			["PCHAR","lpNewFileName","in"],
			["PBLOB","lpProgressRoutine","in"],
			["PBLOB","lpData","in"],
			["DWORD","dwFlags","in"],
			])
		
		railgun.add_function('kernel32',  'MoveFileWithProgressW', 'BOOL',[
			["PWCHAR","lpExistingFileName","in"],
			["PWCHAR","lpNewFileName","in"],
			["PBLOB","lpProgressRoutine","in"],
			["PBLOB","lpData","in"],
			["DWORD","dwFlags","in"],
			])
		
		railgun.add_function('kernel32',  'MulDiv', 'DWORD',[
			["DWORD","nNumber","in"],
			["DWORD","nNumerator","in"],
			["DWORD","nDenominator","in"],
			])
		
		railgun.add_function('kernel32',  'NeedCurrentDirectoryForExePathA', 'BOOL',[
			["PCHAR","ExeName","in"],
			])
		
		railgun.add_function('kernel32',  'NeedCurrentDirectoryForExePathW', 'BOOL',[
			["PWCHAR","ExeName","in"],
			])
		
		railgun.add_function('kernel32',  'OpenEventA', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'OpenEventW', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PWCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'OpenFile', 'DWORD',[
			["PCHAR","lpFileName","in"],
			["PBLOB","lpReOpenBuff","inout"],
			["DWORD","uStyle","in"],
			])
		
		railgun.add_function('kernel32',  'OpenFileMappingA', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'OpenFileMappingW', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PWCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'OpenJobObjectA', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'OpenJobObjectW', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PWCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'OpenMutexA', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'OpenMutexW', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PWCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'OpenProcess', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["DWORD","dwProcessId","in"],
			])
		
		railgun.add_function('kernel32',  'OpenSemaphoreA', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'OpenSemaphoreW', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PWCHAR","lpName","in"],
			])
		
		railgun.add_function('kernel32',  'OpenThread', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["DWORD","dwThreadId","in"],
			])
		
		railgun.add_function('kernel32',  'OpenWaitableTimerA', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PCHAR","lpTimerName","in"],
			])
		
		railgun.add_function('kernel32',  'OpenWaitableTimerW', 'DWORD',[
			["DWORD","dwDesiredAccess","in"],
			["BOOL","bInheritHandle","in"],
			["PWCHAR","lpTimerName","in"],
			])
		
		railgun.add_function('kernel32',  'OutputDebugStringA', 'VOID',[
			["PCHAR","lpOutputString","in"],
			])
		
		railgun.add_function('kernel32',  'OutputDebugStringW', 'VOID',[
			["PWCHAR","lpOutputString","in"],
			])
		
		railgun.add_function('kernel32',  'PeekNamedPipe', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","nBufferSize","in"],
			["PDWORD","lpBytesRead","out"],
			["PDWORD","lpTotalBytesAvail","out"],
			["PDWORD","lpBytesLeftThisMessage","out"],
			])
		
		railgun.add_function('kernel32',  'PostQueuedCompletionStatus', 'BOOL',[
			["DWORD","CompletionPort","in"],
			["DWORD","dwNumberOfBytesTransferred","in"],
			["PDWORD","dwCompletionKey","in"],
			["PBLOB","lpOverlapped","in"],
			])
		
		railgun.add_function('kernel32',  'PrepareTape', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwOperation","in"],
			["BOOL","bImmediate","in"],
			])
		
		railgun.add_function('kernel32',  'ProcessIdToSessionId', 'BOOL',[
			["DWORD","dwProcessId","in"],
			["PDWORD","pSessionId","out"],
			])
		
		railgun.add_function('kernel32',  'PulseEvent', 'BOOL',[
			["DWORD","hEvent","in"],
			])
		
		railgun.add_function('kernel32',  'PurgeComm', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwFlags","in"],
			])
		
		railgun.add_function('kernel32',  'QueryActCtxW', 'BOOL',[
			["DWORD","dwFlags","in"],
			["DWORD","hActCtx","in"],
			["PBLOB","pvSubInstance","in"],
			["DWORD","ulInfoClass","in"],
			["PBLOB","pvBuffer","out"],
			["DWORD","cbBuffer","in"],
			["PDWORD","pcbWrittenOrRequired","out"],
			])
		
		railgun.add_function('kernel32',  'QueryDepthSList', 'WORD',[
			["PBLOB","ListHead","in"],
			])
		
		railgun.add_function('kernel32',  'QueryDosDeviceA', 'DWORD',[
			["PCHAR","lpDeviceName","in"],
			["PCHAR","lpTargetPath","out"],
			["DWORD","ucchMax","in"],
			])
		
		railgun.add_function('kernel32',  'QueryDosDeviceW', 'DWORD',[
			["PWCHAR","lpDeviceName","in"],
			["PWCHAR","lpTargetPath","out"],
			["DWORD","ucchMax","in"],
			])
		
		railgun.add_function('kernel32',  'QueryInformationJobObject', 'BOOL',[
			["DWORD","hJob","in"],
			["PBLOB","JobObjectInformationClass","in"],
			["PBLOB","lpJobObjectInformation","out"],
			["DWORD","cbJobObjectInformationLength","in"],
			["PDWORD","lpReturnLength","out"],
			])
		
		railgun.add_function('kernel32',  'QueryMemoryResourceNotification', 'BOOL',[
			["DWORD","ResourceNotificationHandle","in"],
			["PBLOB","ResourceState","out"],
			])
		
		railgun.add_function('kernel32',  'QueryPerformanceCounter', 'BOOL',[
			["PBLOB","lpPerformanceCount","out"],
			])
		
		railgun.add_function('kernel32',  'QueryPerformanceFrequency', 'BOOL',[
			["PBLOB","lpFrequency","out"],
			])
		
		railgun.add_function('kernel32',  'QueueUserAPC', 'DWORD',[
			["PBLOB","pfnAPC","in"],
			["DWORD","hThread","in"],
			["PDWORD","dwData","in"],
			])
		
		railgun.add_function('kernel32',  'QueueUserWorkItem', 'BOOL',[
			["PBLOB","Function","in"],
			["PBLOB","Context","in"],
			["DWORD","Flags","in"],
			])
		
		railgun.add_function('kernel32',  'RaiseException', 'VOID',[
			["DWORD","dwExceptionCode","in"],
			["DWORD","dwExceptionFlags","in"],
			["DWORD","nNumberOfArguments","in"],
			["PBLOB","lpArguments","in"],
			])
		
		railgun.add_function('kernel32',  'ReOpenFile', 'DWORD',[
			["DWORD","hOriginalFile","in"],
			["DWORD","dwDesiredAccess","in"],
			["DWORD","dwShareMode","in"],
			["DWORD","dwFlagsAndAttributes","in"],
			])
		
		railgun.add_function('kernel32',  'ReadDirectoryChangesW', 'BOOL',[
			["DWORD","hDirectory","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","nBufferLength","in"],
			["BOOL","bWatchSubtree","in"],
			["DWORD","dwNotifyFilter","in"],
			["PDWORD","lpBytesReturned","out"],
			["PBLOB","lpOverlapped","inout"],
			["PBLOB","lpCompletionRoutine","in"],
			])
		
		railgun.add_function('kernel32',  'ReadFile', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","nNumberOfBytesToRead","in"],
			["PDWORD","lpNumberOfBytesRead","out"],
			["PBLOB","lpOverlapped","inout"],
			])
		
		railgun.add_function('kernel32',  'ReadFileEx', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","nNumberOfBytesToRead","in"],
			["PBLOB","lpOverlapped","inout"],
			["PBLOB","lpCompletionRoutine","in"],
			])
		
		railgun.add_function('kernel32',  'ReadFileScatter', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","aSegmentArray[]","in"],
			["DWORD","nNumberOfBytesToRead","in"],
			["PDWORD","lpReserved","inout"],
			["PBLOB","lpOverlapped","inout"],
			])
		
		railgun.add_function('kernel32',  'ReadProcessMemory', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpBaseAddress","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","nSize","in"],
			["PDWORD","lpNumberOfBytesRead","out"],
			])
		
		railgun.add_function('kernel32',  'RegisterWaitForSingleObject', 'BOOL',[
			["PDWORD","phNewWaitObject","out"],
			["DWORD","hObject","in"],
			["PBLOB","Callback","in"],
			["PBLOB","Context","in"],
			["DWORD","dwMilliseconds","in"],
			["DWORD","dwFlags","in"],
			])
		
		railgun.add_function('kernel32',  'RegisterWaitForSingleObjectEx', 'DWORD',[
			["DWORD","hObject","in"],
			["PBLOB","Callback","in"],
			["PBLOB","Context","in"],
			["DWORD","dwMilliseconds","in"],
			["DWORD","dwFlags","in"],
			])
		
		railgun.add_function('kernel32',  'ReleaseActCtx', 'VOID',[
			["DWORD","hActCtx","inout"],
			])
		
		railgun.add_function('kernel32',  'ReleaseMutex', 'BOOL',[
			["DWORD","hMutex","in"],
			])
		
		railgun.add_function('kernel32',  'ReleaseSemaphore', 'BOOL',[
			["DWORD","hSemaphore","in"],
			["DWORD","lReleaseCount","in"],
			["PBLOB","lpPreviousCount","out"],
			])
		
		railgun.add_function('kernel32',  'RemoveDirectoryA', 'BOOL',[
			["PCHAR","lpPathName","in"],
			])
		
		railgun.add_function('kernel32',  'RemoveDirectoryW', 'BOOL',[
			["PWCHAR","lpPathName","in"],
			])
		
		railgun.add_function('kernel32',  'RemoveVectoredContinueHandler', 'DWORD',[
			["PBLOB","Handle","in"],
			])
		
		railgun.add_function('kernel32',  'RemoveVectoredExceptionHandler', 'DWORD',[
			["PBLOB","Handle","in"],
			])
		
		railgun.add_function('kernel32',  'ReplaceFileA', 'BOOL',[
			["PCHAR","lpReplacedFileName","in"],
			["PCHAR","lpReplacementFileName","in"],
			["PCHAR","lpBackupFileName","in"],
			["DWORD","dwReplaceFlags","in"],
			["PBLOB","lpExclude","inout"],
			["PBLOB","lpReserved","inout"],
			])
		
		railgun.add_function('kernel32',  'ReplaceFileW', 'BOOL',[
			["PWCHAR","lpReplacedFileName","in"],
			["PWCHAR","lpReplacementFileName","in"],
			["PWCHAR","lpBackupFileName","in"],
			["DWORD","dwReplaceFlags","in"],
			["PBLOB","lpExclude","inout"],
			["PBLOB","lpReserved","inout"],
			])
		
		railgun.add_function('kernel32',  'RequestDeviceWakeup', 'BOOL',[
			["DWORD","hDevice","in"],
			])
		
		railgun.add_function('kernel32',  'RequestWakeupLatency', 'BOOL',[
			["PBLOB","latency","in"],
			])
		
		railgun.add_function('kernel32',  'ResetEvent', 'BOOL',[
			["DWORD","hEvent","in"],
			])
		
		railgun.add_function('kernel32',  'ResetWriteWatch', 'DWORD',[
			["PBLOB","lpBaseAddress","in"],
			["DWORD","dwRegionSize","in"],
			])
		
		railgun.add_function('kernel32',  'RestoreLastError', 'VOID',[
			["DWORD","dwErrCode","in"],
			])
		
		railgun.add_function('kernel32',  'ResumeThread', 'DWORD',[
			["DWORD","hThread","in"],
			])
		
		railgun.add_function('kernel32',  'SearchPathA', 'DWORD',[
			["PCHAR","lpPath","in"],
			["PCHAR","lpFileName","in"],
			["PCHAR","lpExtension","in"],
			["DWORD","nBufferLength","in"],
			["PCHAR","lpBuffer","out"],
			["PBLOB","lpFilePart","out"],
			])
		
		railgun.add_function('kernel32',  'SearchPathW', 'DWORD',[
			["PWCHAR","lpPath","in"],
			["PWCHAR","lpFileName","in"],
			["PWCHAR","lpExtension","in"],
			["DWORD","nBufferLength","in"],
			["PWCHAR","lpBuffer","out"],
			["PBLOB","lpFilePart","out"],
			])
		
		railgun.add_function('kernel32',  'SetCommBreak', 'BOOL',[
			["DWORD","hFile","in"],
			])
		
		railgun.add_function('kernel32',  'SetCommConfig', 'BOOL',[
			["DWORD","hCommDev","in"],
			["PBLOB","lpCC","in"],
			["DWORD","dwSize","in"],
			])
		
		railgun.add_function('kernel32',  'SetCommMask', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwEvtMask","in"],
			])
		
		railgun.add_function('kernel32',  'SetCommState', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpDCB","in"],
			])
		
		railgun.add_function('kernel32',  'SetCommTimeouts', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpCommTimeouts","in"],
			])
		
		railgun.add_function('kernel32',  'SetComputerNameA', 'BOOL',[
			["PCHAR","lpComputerName","in"],
			])
		
		railgun.add_function('kernel32',  'SetComputerNameExA', 'BOOL',[
			["DWORD","NameType","in"],
			["PCHAR","lpBuffer","in"],
			])
		
		railgun.add_function('kernel32',  'SetComputerNameExW', 'BOOL',[
			["DWORD","NameType","in"],
			["PWCHAR","lpBuffer","in"],
			])
		
		railgun.add_function('kernel32',  'SetComputerNameW', 'BOOL',[
			["PWCHAR","lpComputerName","in"],
			])
		
		railgun.add_function('kernel32',  'SetCriticalSectionSpinCount', 'DWORD',[
			["PBLOB","lpCriticalSection","inout"],
			["DWORD","dwSpinCount","in"],
			])
		
		railgun.add_function('kernel32',  'SetCurrentDirectoryA', 'BOOL',[
			["PCHAR","lpPathName","in"],
			])
		
		railgun.add_function('kernel32',  'SetCurrentDirectoryW', 'BOOL',[
			["PWCHAR","lpPathName","in"],
			])
		
		railgun.add_function('kernel32',  'SetDefaultCommConfigA', 'BOOL',[
			["PCHAR","lpszName","in"],
			["PBLOB","lpCC","in"],
			["DWORD","dwSize","in"],
			])
		
		railgun.add_function('kernel32',  'SetDefaultCommConfigW', 'BOOL',[
			["PWCHAR","lpszName","in"],
			["PBLOB","lpCC","in"],
			["DWORD","dwSize","in"],
			])
		
		railgun.add_function('kernel32',  'SetDllDirectoryA', 'BOOL',[
			["PCHAR","lpPathName","in"],
			])
		
		railgun.add_function('kernel32',  'SetDllDirectoryW', 'BOOL',[
			["PWCHAR","lpPathName","in"],
			])
		
		railgun.add_function('kernel32',  'SetEndOfFile', 'BOOL',[
			["DWORD","hFile","in"],
			])
		
		railgun.add_function('kernel32',  'SetEnvironmentStringsA', 'BOOL',[
			["PBLOB","NewEnvironment","in"],
			])
		
		railgun.add_function('kernel32',  'SetEnvironmentStringsW', 'BOOL',[
			["PBLOB","NewEnvironment","in"],
			])
		
		railgun.add_function('kernel32',  'SetEnvironmentVariableA', 'BOOL',[
			["PCHAR","lpName","in"],
			["PCHAR","lpValue","in"],
			])
		
		railgun.add_function('kernel32',  'SetEnvironmentVariableW', 'BOOL',[
			["PWCHAR","lpName","in"],
			["PWCHAR","lpValue","in"],
			])
		
		railgun.add_function('kernel32',  'SetErrorMode', 'DWORD',[
			["DWORD","uMode","in"],
			])
		
		railgun.add_function('kernel32',  'SetEvent', 'BOOL',[
			["DWORD","hEvent","in"],
			])
		
		railgun.add_function('kernel32',  'SetFileApisToANSI', 'VOID',[
			])
		
		railgun.add_function('kernel32',  'SetFileApisToOEM', 'VOID',[
			])
		
		railgun.add_function('kernel32',  'SetFileAttributesA', 'BOOL',[
			["PCHAR","lpFileName","in"],
			["DWORD","dwFileAttributes","in"],
			])
		
		railgun.add_function('kernel32',  'SetFileAttributesW', 'BOOL',[
			["PWCHAR","lpFileName","in"],
			["DWORD","dwFileAttributes","in"],
			])
		
		railgun.add_function('kernel32',  'SetFilePointer', 'DWORD',[
			["DWORD","hFile","in"],
			["DWORD","lDistanceToMove","in"],
			["PDWORD","lpDistanceToMoveHigh","in"],
			["DWORD","dwMoveMethod","in"],
			])
		
		railgun.add_function('kernel32',  'SetFilePointerEx', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","liDistanceToMove","in"],
			["PBLOB","lpNewFilePointer","out"],
			["DWORD","dwMoveMethod","in"],
			])
		
		railgun.add_function('kernel32',  'SetFileShortNameA', 'BOOL',[
			["DWORD","hFile","in"],
			["PCHAR","lpShortName","in"],
			])
		
		railgun.add_function('kernel32',  'SetFileShortNameW', 'BOOL',[
			["DWORD","hFile","in"],
			["PWCHAR","lpShortName","in"],
			])
		
		railgun.add_function('kernel32',  'SetFileTime', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpCreationTime","in"],
			["PBLOB","lpLastAccessTime","in"],
			["PBLOB","lpLastWriteTime","in"],
			])
		
		railgun.add_function('kernel32',  'SetFileValidData', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","ValidDataLength","in"],
			])
		
		railgun.add_function('kernel32',  'SetFirmwareEnvironmentVariableA', 'BOOL',[
			["PCHAR","lpName","in"],
			["PCHAR","lpGuid","in"],
			["PBLOB","pValue","in"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'SetFirmwareEnvironmentVariableW', 'BOOL',[
			["PWCHAR","lpName","in"],
			["PWCHAR","lpGuid","in"],
			["PBLOB","pValue","in"],
			["DWORD","nSize","in"],
			])
		
		railgun.add_function('kernel32',  'SetHandleCount', 'DWORD',[
			["DWORD","uNumber","in"],
			])
		
		railgun.add_function('kernel32',  'SetHandleInformation', 'BOOL',[
			["DWORD","hObject","in"],
			["DWORD","dwMask","in"],
			["DWORD","dwFlags","in"],
			])
		
		railgun.add_function('kernel32',  'SetInformationJobObject', 'BOOL',[
			["DWORD","hJob","in"],
			["PBLOB","JobObjectInformationClass","in"],
			["PBLOB","lpJobObjectInformation","in"],
			["DWORD","cbJobObjectInformationLength","in"],
			])
		
		railgun.add_function('kernel32',  'SetLastError', 'VOID',[
			["DWORD","dwErrCode","in"],
			])
		
		railgun.add_function('kernel32',  'SetLocalTime', 'BOOL',[
			["PBLOB","lpSystemTime","in"],
			])
		
		railgun.add_function('kernel32',  'SetMailslotInfo', 'BOOL',[
			["DWORD","hMailslot","in"],
			["DWORD","lReadTimeout","in"],
			])
		
		railgun.add_function('kernel32',  'SetMessageWaitingIndicator', 'BOOL',[
			["DWORD","hMsgIndicator","in"],
			["DWORD","ulMsgCount","in"],
			])
		
		railgun.add_function('kernel32',  'SetNamedPipeHandleState', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			["PDWORD","lpMode","in"],
			["PDWORD","lpMaxCollectionCount","in"],
			["PDWORD","lpCollectDataTimeout","in"],
			])
		
		railgun.add_function('kernel32',  'SetPriorityClass', 'BOOL',[
			["DWORD","hProcess","in"],
			["DWORD","dwPriorityClass","in"],
			])
		
		railgun.add_function('kernel32',  'SetProcessAffinityMask', 'BOOL',[
			["DWORD","hProcess","in"],
			["PDWORD","dwProcessAffinityMask","in"],
			])
		
		railgun.add_function('kernel32',  'SetProcessPriorityBoost', 'BOOL',[
			["DWORD","hProcess","in"],
			["BOOL","bDisablePriorityBoost","in"],
			])
		
		railgun.add_function('kernel32',  'SetProcessShutdownParameters', 'BOOL',[
			["DWORD","dwLevel","in"],
			["DWORD","dwFlags","in"],
			])
		
		railgun.add_function('kernel32',  'SetProcessWorkingSetSize', 'BOOL',[
			["DWORD","hProcess","in"],
			["DWORD","dwMinimumWorkingSetSize","in"],
			["DWORD","dwMaximumWorkingSetSize","in"],
			])
		
		railgun.add_function('kernel32',  'SetProcessWorkingSetSizeEx', 'BOOL',[
			["DWORD","hProcess","in"],
			["DWORD","dwMinimumWorkingSetSize","in"],
			["DWORD","dwMaximumWorkingSetSize","in"],
			["DWORD","Flags","in"],
			])
		
		railgun.add_function('kernel32',  'SetStdHandle', 'BOOL',[
			["DWORD","nStdHandle","in"],
			["DWORD","hHandle","in"],
			])
		
		railgun.add_function('kernel32',  'SetSystemFileCacheSize', 'BOOL',[
			["DWORD","MinimumFileCacheSize","in"],
			["DWORD","MaximumFileCacheSize","in"],
			["DWORD","Flags","in"],
			])
		
		railgun.add_function('kernel32',  'SetSystemPowerState', 'BOOL',[
			["BOOL","fSuspend","in"],
			["BOOL","fForce","in"],
			])
		
		railgun.add_function('kernel32',  'SetSystemTime', 'BOOL',[
			["PBLOB","lpSystemTime","in"],
			])
		
		railgun.add_function('kernel32',  'SetSystemTimeAdjustment', 'BOOL',[
			["DWORD","dwTimeAdjustment","in"],
			["BOOL","bTimeAdjustmentDisabled","in"],
			])
		
		railgun.add_function('kernel32',  'SetTapeParameters', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwOperation","in"],
			["PBLOB","lpTapeInformation","in"],
			])
		
		railgun.add_function('kernel32',  'SetTapePosition', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwPositionMethod","in"],
			["DWORD","dwPartition","in"],
			["DWORD","dwOffsetLow","in"],
			["DWORD","dwOffsetHigh","in"],
			["BOOL","bImmediate","in"],
			])
		
		railgun.add_function('kernel32',  'SetThreadAffinityMask', 'PDWORD',[
			["DWORD","hThread","in"],
			["PDWORD","dwThreadAffinityMask","in"],
			])
		
		railgun.add_function('kernel32',  'SetThreadContext', 'BOOL',[
			["DWORD","hThread","in"],
			["PBLOB","lpContext","in"],
			])
		
		railgun.add_function('kernel32',  'SetThreadExecutionState', 'DWORD',[
			["DWORD","esFlags","in"],
			])
		
		railgun.add_function('kernel32',  'SetThreadIdealProcessor', 'DWORD',[
			["DWORD","hThread","in"],
			["DWORD","dwIdealProcessor","in"],
			])
		
		railgun.add_function('kernel32',  'SetThreadPriority', 'BOOL',[
			["DWORD","hThread","in"],
			["DWORD","nPriority","in"],
			])
		
		railgun.add_function('kernel32',  'SetThreadPriorityBoost', 'BOOL',[
			["DWORD","hThread","in"],
			["BOOL","bDisablePriorityBoost","in"],
			])
		
		railgun.add_function('kernel32',  'SetThreadStackGuarantee', 'BOOL',[
			["PDWORD","StackSizeInBytes","inout"],
			])
		
		railgun.add_function('kernel32',  'SetTimeZoneInformation', 'BOOL',[
			["PBLOB","lpTimeZoneInformation","in"],
			])
		
		railgun.add_function('kernel32',  'SetTimerQueueTimer', 'DWORD',[
			["DWORD","TimerQueue","in"],
			["PBLOB","Callback","in"],
			["PBLOB","Parameter","in"],
			["DWORD","DueTime","in"],
			["DWORD","Period","in"],
			["BOOL","PreferIo","in"],
			])
		
		railgun.add_function('kernel32',  'SetUnhandledExceptionFilter', 'PBLOB',[
			["PBLOB","lpTopLevelExceptionFilter","in"],
			])
		
		railgun.add_function('kernel32',  'SetVolumeLabelA', 'BOOL',[
			["PCHAR","lpRootPathName","in"],
			["PCHAR","lpVolumeName","in"],
			])
		
		railgun.add_function('kernel32',  'SetVolumeLabelW', 'BOOL',[
			["PWCHAR","lpRootPathName","in"],
			["PWCHAR","lpVolumeName","in"],
			])
		
		railgun.add_function('kernel32',  'SetVolumeMountPointA', 'BOOL',[
			["PCHAR","lpszVolumeMountPoint","in"],
			["PCHAR","lpszVolumeName","in"],
			])
		
		railgun.add_function('kernel32',  'SetVolumeMountPointW', 'BOOL',[
			["PWCHAR","lpszVolumeMountPoint","in"],
			["PWCHAR","lpszVolumeName","in"],
			])
		
		railgun.add_function('kernel32',  'SetWaitableTimer', 'BOOL',[
			["DWORD","hTimer","in"],
			["PBLOB","lpDueTime","in"],
			["DWORD","lPeriod","in"],
			["PBLOB","pfnCompletionRoutine","in"],
			["PBLOB","lpArgToCompletionRoutine","in"],
			["BOOL","fResume","in"],
			])
		
		railgun.add_function('kernel32',  'SetupComm', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwInQueue","in"],
			["DWORD","dwOutQueue","in"],
			])
		
		railgun.add_function('kernel32',  'SignalObjectAndWait', 'DWORD',[
			["DWORD","hObjectToSignal","in"],
			["DWORD","hObjectToWaitOn","in"],
			["DWORD","dwMilliseconds","in"],
			["BOOL","bAlertable","in"],
			])
		
		railgun.add_function('kernel32',  'SizeofResource', 'DWORD',[
			["DWORD","hModule","in"],
			["DWORD","hResInfo","in"],
			])
		
		railgun.add_function('kernel32',  'Sleep', 'VOID',[
			["DWORD","dwMilliseconds","in"],
			])
		
		railgun.add_function('kernel32',  'SleepEx', 'DWORD',[
			["DWORD","dwMilliseconds","in"],
			["BOOL","bAlertable","in"],
			])
		
		railgun.add_function('kernel32',  'SuspendThread', 'DWORD',[
			["DWORD","hThread","in"],
			])
		
		railgun.add_function('kernel32',  'SwitchToFiber', 'VOID',[
			["PBLOB","lpFiber","in"],
			])
		
		railgun.add_function('kernel32',  'SwitchToThread', 'BOOL',[
			])
		
		railgun.add_function('kernel32',  'SystemTimeToFileTime', 'BOOL',[
			["PBLOB","lpSystemTime","in"],
			["PBLOB","lpFileTime","out"],
			])
		
		railgun.add_function('kernel32',  'SystemTimeToTzSpecificLocalTime', 'BOOL',[
			["PBLOB","lpTimeZoneInformation","in"],
			["PBLOB","lpUniversalTime","in"],
			["PBLOB","lpLocalTime","out"],
			])
		
		railgun.add_function('kernel32',  'TerminateJobObject', 'BOOL',[
			["DWORD","hJob","in"],
			["DWORD","uExitCode","in"],
			])
		
		railgun.add_function('kernel32',  'TerminateProcess', 'BOOL',[
			["DWORD","hProcess","in"],
			["DWORD","uExitCode","in"],
			])
		
		railgun.add_function('kernel32',  'TerminateThread', 'BOOL',[
			["DWORD","hThread","in"],
			["DWORD","dwExitCode","in"],
			])
		
		railgun.add_function('kernel32',  'TlsAlloc', 'DWORD',[
			])
		
		railgun.add_function('kernel32',  'TlsFree', 'BOOL',[
			["DWORD","dwTlsIndex","in"],
			])
		
		railgun.add_function('kernel32',  'TlsGetValue', 'PBLOB',[
			["DWORD","dwTlsIndex","in"],
			])
		
		railgun.add_function('kernel32',  'TlsSetValue', 'BOOL',[
			["DWORD","dwTlsIndex","in"],
			["PBLOB","lpTlsValue","in"],
			])
		
		railgun.add_function('kernel32',  'TransactNamedPipe', 'BOOL',[
			["DWORD","hNamedPipe","in"],
			["PBLOB","lpInBuffer","in"],
			["DWORD","nInBufferSize","in"],
			["PBLOB","lpOutBuffer","out"],
			["DWORD","nOutBufferSize","in"],
			["PDWORD","lpBytesRead","out"],
			["PBLOB","lpOverlapped","inout"],
			])
		
		railgun.add_function('kernel32',  'TransmitCommChar', 'BOOL',[
			["DWORD","hFile","in"],
			["BYTE","cChar","in"],
			])
		
		railgun.add_function('kernel32',  'TryEnterCriticalSection', 'BOOL',[
			["PBLOB","lpCriticalSection","inout"],
			])
		
		railgun.add_function('kernel32',  'TzSpecificLocalTimeToSystemTime', 'BOOL',[
			["PBLOB","lpTimeZoneInformation","in"],
			["PBLOB","lpLocalTime","in"],
			["PBLOB","lpUniversalTime","out"],
			])
		
		railgun.add_function('kernel32',  'UnhandledExceptionFilter', 'DWORD',[
			["PBLOB","ExceptionInfo","in"],
			])
		
		railgun.add_function('kernel32',  'UnlockFile', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwFileOffsetLow","in"],
			["DWORD","dwFileOffsetHigh","in"],
			["DWORD","nNumberOfBytesToUnlockLow","in"],
			["DWORD","nNumberOfBytesToUnlockHigh","in"],
			])
		
		railgun.add_function('kernel32',  'UnlockFileEx', 'BOOL',[
			["DWORD","hFile","in"],
			["DWORD","dwReserved","inout"],
			["DWORD","nNumberOfBytesToUnlockLow","in"],
			["DWORD","nNumberOfBytesToUnlockHigh","in"],
			["PBLOB","lpOverlapped","inout"],
			])
		
		railgun.add_function('kernel32',  'UnmapViewOfFile', 'BOOL',[
			["PBLOB","lpBaseAddress","in"],
			])
		
		railgun.add_function('kernel32',  'UnregisterWait', 'BOOL',[
			["DWORD","WaitHandle","in"],
			])
		
		railgun.add_function('kernel32',  'UnregisterWaitEx', 'BOOL',[
			["DWORD","WaitHandle","in"],
			["DWORD","CompletionEvent","in"],
			])
		
		railgun.add_function('kernel32',  'UpdateResourceA', 'BOOL',[
			["DWORD","hUpdate","in"],
			["PCHAR","lpType","in"],
			["PCHAR","lpName","in"],
			["WORD","wLanguage","in"],
			["PBLOB","lpData","in"],
			["DWORD","cb","in"],
			])
		
		railgun.add_function('kernel32',  'UpdateResourceW', 'BOOL',[
			["DWORD","hUpdate","in"],
			["PWCHAR","lpType","in"],
			["PWCHAR","lpName","in"],
			["WORD","wLanguage","in"],
			["PBLOB","lpData","in"],
			["DWORD","cb","in"],
			])
		
		railgun.add_function('kernel32',  'VerifyVersionInfoA', 'BOOL',[
			["PBLOB","lpVersionInformation","inout"],
			["DWORD","dwTypeMask","in"],
			["PBLOB","dwlConditionMask","in"],
			])
		
		railgun.add_function('kernel32',  'VerifyVersionInfoW', 'BOOL',[
			["PBLOB","lpVersionInformation","inout"],
			["DWORD","dwTypeMask","in"],
			["PBLOB","dwlConditionMask","in"],
			])
		
		railgun.add_function('kernel32',  'VirtualAlloc', 'PBLOB',[
			["PBLOB","lpAddress","in"],
			["DWORD","dwSize","in"],
			["DWORD","flAllocationType","in"],
			["DWORD","flProtect","in"],
			])
		
		railgun.add_function('kernel32',  'VirtualAllocEx', 'PBLOB',[
			["DWORD","hProcess","in"],
			["PBLOB","lpAddress","in"],
			["DWORD","dwSize","in"],
			["DWORD","flAllocationType","in"],
			["DWORD","flProtect","in"],
			])
		
		railgun.add_function('kernel32',  'VirtualFree', 'BOOL',[
			["PBLOB","lpAddress","in"],
			["DWORD","dwSize","in"],
			["DWORD","dwFreeType","in"],
			])
		
		railgun.add_function('kernel32',  'VirtualFreeEx', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpAddress","in"],
			["DWORD","dwSize","in"],
			["DWORD","dwFreeType","in"],
			])
		
		railgun.add_function('kernel32',  'VirtualLock', 'BOOL',[
			["PBLOB","lpAddress","in"],
			["DWORD","dwSize","in"],
			])
		
		railgun.add_function('kernel32',  'VirtualProtect', 'BOOL',[
			["PBLOB","lpAddress","in"],
			["DWORD","dwSize","in"],
			["DWORD","flNewProtect","in"],
			["PDWORD","lpflOldProtect","out"],
			])
		
		railgun.add_function('kernel32',  'VirtualProtectEx', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpAddress","in"],
			["DWORD","dwSize","in"],
			["DWORD","flNewProtect","in"],
			["PDWORD","lpflOldProtect","out"],
			])
		
		railgun.add_function('kernel32',  'VirtualQuery', 'DWORD',[
			["PBLOB","lpAddress","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","dwLength","in"],
			])
		
		railgun.add_function('kernel32',  'VirtualQueryEx', 'DWORD',[
			["DWORD","hProcess","in"],
			["PBLOB","lpAddress","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","dwLength","in"],
			])
		
		railgun.add_function('kernel32',  'VirtualUnlock', 'BOOL',[
			["PBLOB","lpAddress","in"],
			["DWORD","dwSize","in"],
			])
		
		railgun.add_function('kernel32',  'WTSGetActiveConsoleSessionId', 'DWORD',[
			])
		
		railgun.add_function('kernel32',  'WaitCommEvent', 'BOOL',[
			["DWORD","hFile","in"],
			["PDWORD","lpEvtMask","inout"],
			["PBLOB","lpOverlapped","inout"],
			])
		
		railgun.add_function('kernel32',  'WaitForDebugEvent', 'BOOL',[
			["PBLOB","lpDebugEvent","in"],
			["DWORD","dwMilliseconds","in"],
			])
		
		railgun.add_function('kernel32',  'WaitForMultipleObjects', 'DWORD',[
			["DWORD","nCount","in"],
			["PDWORD","lpHandles","in"],
			["BOOL","bWaitAll","in"],
			["DWORD","dwMilliseconds","in"],
			])
		
		railgun.add_function('kernel32',  'WaitForMultipleObjectsEx', 'DWORD',[
			["DWORD","nCount","in"],
			["PDWORD","lpHandles","in"],
			["BOOL","bWaitAll","in"],
			["DWORD","dwMilliseconds","in"],
			["BOOL","bAlertable","in"],
			])
		
		railgun.add_function('kernel32',  'WaitForSingleObject', 'DWORD',[
			["DWORD","hHandle","in"],
			["DWORD","dwMilliseconds","in"],
			])
		
		railgun.add_function('kernel32',  'WaitForSingleObjectEx', 'DWORD',[
			["DWORD","hHandle","in"],
			["DWORD","dwMilliseconds","in"],
			["BOOL","bAlertable","in"],
			])
		
		railgun.add_function('kernel32',  'WaitNamedPipeA', 'BOOL',[
			["PCHAR","lpNamedPipeName","in"],
			["DWORD","nTimeOut","in"],
			])
		
		railgun.add_function('kernel32',  'WaitNamedPipeW', 'BOOL',[
			["PWCHAR","lpNamedPipeName","in"],
			["DWORD","nTimeOut","in"],
			])
		
		railgun.add_function('kernel32',  'WinExec', 'DWORD',[
			["PCHAR","lpCmdLine","in"],
			["DWORD","uCmdShow","in"],
			])
		
		railgun.add_function('kernel32',  'Wow64DisableWow64FsRedirection', 'BOOL',[
			["PBLOB","OldValue","out"],
			])
		
		railgun.add_function('kernel32',  'Wow64EnableWow64FsRedirection', 'BOOL',[
			["BOOL","Wow64FsEnableRedirection","in"],
			])
		
		railgun.add_function('kernel32',  'Wow64RevertWow64FsRedirection', 'BOOL',[
			["PBLOB","OlValue","in"],
			])
		
		railgun.add_function('kernel32',  'WriteFile', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","in"],
			["DWORD","nNumberOfBytesToWrite","in"],
			["PDWORD","lpNumberOfBytesWritten","out"],
			["PBLOB","lpOverlapped","inout"],
			])
		
		railgun.add_function('kernel32',  'WriteFileEx', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","in"],
			["DWORD","nNumberOfBytesToWrite","in"],
			["PBLOB","lpOverlapped","inout"],
			["PBLOB","lpCompletionRoutine","in"],
			])
		
		railgun.add_function('kernel32',  'WriteFileGather', 'BOOL',[
			["DWORD","hFile","in"],
			["PBLOB","aSegmentArray[]","in"],
			["DWORD","nNumberOfBytesToWrite","in"],
			["PDWORD","lpReserved","inout"],
			["PBLOB","lpOverlapped","inout"],
			])
		
		railgun.add_function('kernel32',  'WritePrivateProfileSectionA', 'BOOL',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpString","in"],
			["PCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'WritePrivateProfileSectionW', 'BOOL',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpString","in"],
			["PWCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'WritePrivateProfileStringA', 'BOOL',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpKeyName","in"],
			["PCHAR","lpString","in"],
			["PCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'WritePrivateProfileStringW', 'BOOL',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpKeyName","in"],
			["PWCHAR","lpString","in"],
			["PWCHAR","lpFileName","in"],
			])
		
		railgun.add_function('kernel32',  'WritePrivateProfileStructA', 'BOOL',[
			["PCHAR","lpszSection","in"],
			["PCHAR","lpszKey","in"],
			["PBLOB","lpStruct","in"],
			["DWORD","uSizeStruct","in"],
			["PCHAR","szFile","in"],
			])
		
		railgun.add_function('kernel32',  'WritePrivateProfileStructW', 'BOOL',[
			["PWCHAR","lpszSection","in"],
			["PWCHAR","lpszKey","in"],
			["PBLOB","lpStruct","in"],
			["DWORD","uSizeStruct","in"],
			["PWCHAR","szFile","in"],
			])
		
		railgun.add_function('kernel32',  'WriteProcessMemory', 'BOOL',[
			["DWORD","hProcess","in"],
			["PBLOB","lpBaseAddress","in"],
			["PBLOB","lpBuffer","in"],
			["DWORD","nSize","in"],
			["PDWORD","lpNumberOfBytesWritten","out"],
			])
		
		railgun.add_function('kernel32',  'WriteProfileSectionA', 'BOOL',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpString","in"],
			])
		
		railgun.add_function('kernel32',  'WriteProfileSectionW', 'BOOL',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpString","in"],
			])
		
		railgun.add_function('kernel32',  'WriteProfileStringA', 'BOOL',[
			["PCHAR","lpAppName","in"],
			["PCHAR","lpKeyName","in"],
			["PCHAR","lpString","in"],
			])
		
		railgun.add_function('kernel32',  'WriteProfileStringW', 'BOOL',[
			["PWCHAR","lpAppName","in"],
			["PWCHAR","lpKeyName","in"],
			["PWCHAR","lpString","in"],
			])
		
		railgun.add_function('kernel32',  'WriteTapemark', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","dwTapemarkType","in"],
			["DWORD","dwTapemarkCount","in"],
			["BOOL","bImmediate","in"],
			])
		
		railgun.add_function('kernel32',  'ZombifyActCtx', 'BOOL',[
			["DWORD","hActCtx","inout"],
			])
		
		railgun.add_function('kernel32',  '_hread', 'DWORD',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","lBytes","in"],
			])
		
		railgun.add_function('kernel32',  '_hwrite', 'DWORD',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","in"],
			["DWORD","lBytes","in"],
			])
		
		railgun.add_function('kernel32',  '_lclose', 'DWORD',[
			["DWORD","hFile","in"],
			])
		
		railgun.add_function('kernel32',  '_lcreat', 'DWORD',[
			["PCHAR","lpPathName","in"],
			["DWORD","iAttribute","in"],
			])
		
		railgun.add_function('kernel32',  '_llseek', 'DWORD',[
			["DWORD","hFile","in"],
			["DWORD","lOffset","in"],
			["DWORD","iOrigin","in"],
			])
		
		railgun.add_function('kernel32',  '_lopen', 'DWORD',[
			["PCHAR","lpPathName","in"],
			["DWORD","iReadWrite","in"],
			])
		
		railgun.add_function('kernel32',  '_lread', 'DWORD',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","out"],
			["DWORD","uBytes","in"],
			])
		
		railgun.add_function('kernel32',  '_lwrite', 'DWORD',[
			["DWORD","hFile","in"],
			["PBLOB","lpBuffer","in"],
			["DWORD","uBytes","in"],
			])
		
		railgun.add_function('kernel32',  'lstrcatA', 'PCHAR',[
			["PCHAR","lpString1","inout"],
			["PCHAR","lpString2","in"],
			])
		
		railgun.add_function('kernel32',  'lstrcatW', 'PWCHAR',[
			["PWCHAR","lpString1","inout"],
			["PWCHAR","lpString2","in"],
			])
		
		railgun.add_function('kernel32',  'lstrcmpA', 'DWORD',[
			["PCHAR","lpString1","in"],
			["PCHAR","lpString2","in"],
			])
		
		railgun.add_function('kernel32',  'lstrcmpW', 'DWORD',[
			["PWCHAR","lpString1","in"],
			["PWCHAR","lpString2","in"],
			])
		
		railgun.add_function('kernel32',  'lstrcmpiA', 'DWORD',[
			["PCHAR","lpString1","in"],
			["PCHAR","lpString2","in"],
			])
		
		railgun.add_function('kernel32',  'lstrcmpiW', 'DWORD',[
			["PWCHAR","lpString1","in"],
			["PWCHAR","lpString2","in"],
			])
		
		railgun.add_function('kernel32',  'lstrcpyA', 'PCHAR',[
			["PCHAR","lpString1","out"],
			["PCHAR","lpString2","in"],
			])
		
		railgun.add_function('kernel32',  'lstrcpyW', 'PWCHAR',[
			["PWCHAR","lpString1","out"],
			["PWCHAR","lpString2","in"],
			])
		
		railgun.add_function('kernel32',  'lstrcpynA', 'PCHAR',[
			["PCHAR","lpString1","out"],
			["PCHAR","lpString2","in"],
			["DWORD","iMaxLength","in"],
			])
		
		railgun.add_function('kernel32',  'lstrcpynW', 'PWCHAR',[
			["PWCHAR","lpString1","out"],
			["PWCHAR","lpString2","in"],
			["DWORD","iMaxLength","in"],
			])
		
		railgun.add_function('kernel32',  'lstrlenA', 'DWORD',[
			["PCHAR","lpString","in"],
			])
		
		railgun.add_function('kernel32',  'lstrlenW', 'DWORD',[
			["PWCHAR","lpString","in"],
			])
	end # method
end #class

end # 5x module
end
end
end
end


