require 'windows/api'

module Windows
  module Thread
    API.auto_namespace = 'Windows::Thread'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    SYNCHRONIZE                 = 0x00100000
    THREAD_ALL_ACCESS           = 0x1F03FF
    THREAD_DIRECT_IMPERSONATION = 0x0200
    THREAD_GET_CONTEXT          = 0x0008
    THREAD_IMPERSONATE          = 0x0100
    THREAD_QUERY_INFORMATION    = 0x0040
    THREAD_SET_CONTEXT          = 0x0010
    THREAD_SET_INFORMATION      = 0x0020
    THREAD_SET_THREAD_TOKEN     = 0x0080
    THREAD_SUSPEND_RESUME       = 0x0002
    THREAD_TERMINATE            = 0x0001

    THREAD_PRIORITY_ABOVE_NORMAL  = 1
    THREAD_PRIORITY_BELOW_NORMAL  = -1
    THREAD_PRIORITY_HIGHEST       = 2
    THREAD_PRIORITY_IDLE          = -15
    THREAD_PRIORITY_LOWEST        = -2
    THREAD_PRIORITY_NORMAL        = 0
    THREAD_PRIORITY_TIME_CRITICAL = 15
      
    API.new('CreateRemoteThread', 'LPLLPLP', 'L')
    API.new('CreateThread', 'PLKPLP', 'L')
    API.new('ExitThread', 'L', 'V')
    API.new('GetCurrentThread', 'V', 'L')
    API.new('GetCurrentThreadId', 'V', 'L')
    API.new('GetExitCodeThread', 'LP', 'B')
    API.new('GetThreadPriority', 'L', 'I')
    API.new('GetThreadPriorityBoost', 'LP', 'B')
    API.new('GetThreadTimes', 'LPPPP', 'B')
    API.new('OpenThread', 'LIL', 'L')
    API.new('ResumeThread', 'L', 'L')
    API.new('SetThreadAffinityMask', 'LP', 'P')
    API.new('SetThreadIdealProcessor', 'LL', 'L')
    API.new('SetThreadPriority', 'LI', 'B')
    API.new('SetThreadPriorityBoost', 'LI', 'B')
    API.new('Sleep', 'L', 'V')
    API.new('SleepEx', 'LI', 'L')
    API.new('SuspendThread', 'L', 'L')
    API.new('SwitchToThread', 'V', 'B')
    API.new('TerminateThread', 'LL', 'B')
    API.new('TlsAlloc', 'V', 'L')
    API.new('TlsFree', 'L', 'B')
    API.new('TlsGetValue', 'L', 'L')
    API.new('TlsSetValue', 'LL', 'B')

    begin
      API.new('AttachThreadInput', 'LLI', 'B', 'user32')
      API.new('GetThreadIOPendingFlag', 'LP', 'B')
    rescue Win32::API::LoadLibraryError
      # Windows XP or later
    end
  end
end
