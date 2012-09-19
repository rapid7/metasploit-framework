require 'windows/api'

# The Windows module serves as a namespace only.
module Windows
  # The Process module includes process related functions and constants,
  # including some tool help functions that relate to processes.
  module Process
    API.auto_namespace = 'Windows::Process'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    # Process access rights

    PROCESS_ALL_ACCESS                = 0x1F0FFF
    PROCESS_CREATE_PROCESS            = 0x0080
    PROCESS_CREATE_THREAD             = 0x0002
    PROCESS_DUP_HANDLE                = 0x0040
    PROCESS_QUERY_INFORMATION         = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_SET_QUOTA                 = 0x0100
    PROCESS_SET_INFORMATION           = 0x0200
    PROCESS_SUSPEND_RESUME            = 0x0800
    PROCESS_TERMINATE                 = 0x0001
    PROCESS_VM_OPERATION              = 0x0008
    PROCESS_VM_READ                   = 0x0010
    PROCESS_VM_WRITE                  = 0x0020
    SYNCHRONIZE                       = 1048576
    STILL_ACTIVE                      = 259

    # Process priority flags

    ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000
    BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
    HIGH_PRIORITY_CLASS         = 0x00000080
    IDLE_PRIORITY_CLASS         = 0x00000040
    NORMAL_PRIORITY_CLASS       = 0x00000020
    REALTIME_PRIORITY_CLASS     = 0x00000100

    # Process creation flags

    CREATE_BREAKAWAY_FROM_JOB        = 0x01000000
    CREATE_DEFAULT_ERROR_MODE        = 0x04000000
    CREATE_NEW_CONSOLE               = 0x00000010
    CREATE_NEW_PROCESS_GROUP         = 0x00000200
    CREATE_NO_WINDOW                 = 0x08000000
    CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000
    CREATE_SEPARATE_WOW_VDM          = 0x00000800
    CREATE_SHARED_WOW_VDM            = 0x00001000
    CREATE_SUSPENDED                 = 0x00000004
    CREATE_UNICODE_ENVIRONMENT       = 0x00000400
    DEBUG_ONLY_THIS_PROCESS          = 0x00000002
    DEBUG_PROCESS                    = 0x00000001
    DETACHED_PROCESS                 = 0x00000008

    STARTF_USESHOWWINDOW    = 0x00000001
    STARTF_USESIZE          = 0x00000002
    STARTF_USEPOSITION      = 0x00000004
    STARTF_USECOUNTCHARS    = 0x00000008
    STARTF_USEFILLATTRIBUTE = 0x00000010
    STARTF_RUNFULLSCREEN    = 0x00000020
    STARTF_FORCEONFEEDBACK  = 0x00000040
    STARTF_FORCEOFFFEEDBACK = 0x00000080
    STARTF_USESTDHANDLES    = 0x00000100
    STARTF_USEHOTKEY        = 0x00000200

    LOGON_WITH_PROFILE        = 0x00000001
    LOGON_NETCREDENTIALS_ONLY = 0x00000002

    SHUTDOWN_NORETRY = 0x00000001

    # Job Object Classes

    JobObjectBasicLimitInformation               = 2
    JobObjectBasicUIRestrictions                 = 4
    JobObjectSecurityLimitInformation            = 5
    JobObjectEndOfJobTimeInformation             = 6
    JobObjectAssociateCompletionPortInformation  = 7
    JobObjectExtendedLimitInformation            = 9
    JobObjectGroupInformation                    = 11

    # Job Limit Flags

    JOB_OBJECT_LIMIT_WORKINGSET                  = 0x00000001
    JOB_OBJECT_LIMIT_PROCESS_TIME                = 0x00000002
    JOB_OBJECT_LIMIT_JOB_TIME                    = 0x00000004
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS              = 0x00000008
    JOB_OBJECT_LIMIT_AFFINITY                    = 0x00000010
    JOB_OBJECT_LIMIT_PRIORITY_CLASS              = 0x00000020
    JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME           = 0x00000040
    JOB_OBJECT_LIMIT_SCHEDULING_CLASS            = 0x00000080
    JOB_OBJECT_LIMIT_PROCESS_MEMORY              = 0x00000100
    JOB_OBJECT_LIMIT_JOB_MEMORY                  = 0x00000200
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION  = 0x00000400
    JOB_OBJECT_LIMIT_BREAKAWAY_OK                = 0x00000800
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK         = 0x00001000
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE           = 0x00002000

    # Job Access Rights

    JOB_OBJECT_ASSIGN_PROCESS          = 0x0001
    JOB_OBJECT_SET_ATTRIBUTES          = 0x0002
    JOB_OBJECT_QUERY                   = 0x0004
    JOB_OBJECT_TERMINATE               = 0x0008
    JOB_OBJECT_SET_SECURITY_ATTRIBUTES = 0x0010
    JOB_OBJECT_ALL_ACCESS              = 0x1F001F

    # Functions

    API.new('AssignProcessToJobObject', 'LL', 'B')
    API.new('CreateJobObject', 'PS', 'L')
    API.new('CreateProcess', 'PPPPLLLPPP', 'B')
    API.new('CreateProcessAsUser', 'LPPLLILPPPP', 'B', 'advapi32')
    API.new('CreateProcessWithLogonW', 'PPPLPPLLPPP', 'B', 'advapi32')
    API.new('EnumProcesses', 'PLP', 'B', 'psapi')
    API.new('ExitProcess', 'L', 'V')
    API.new('FreeEnvironmentStrings', 'P', 'B')
    API.new('GetCommandLine', 'V', 'P')
    API.new('GetCurrentProcess', 'V', 'L')
    API.new('GetCurrentProcessId', 'V', 'L')
    API.new('GetEnvironmentStrings', 'V', 'L')
    API.new('GetEnvironmentVariable', 'PPL', 'L')
    API.new('GetExitCodeProcess', 'LP', 'B')
    API.new('GetGuiResources', 'LL', 'L', 'user32')
    API.new('GetPriorityClass', 'L', 'L')
    API.new('GetProcessAffinityMask', 'LPP', 'B')
    API.new('GetProcessIoCounters', 'LP', 'B')
    API.new('GetProcessPriorityBoost', 'LP', 'B')
    API.new('GetProcessShutdownParameters', 'PP', 'B')
    API.new('GetProcessTimes', 'LPPPP', 'B')
    API.new('GetProcessVersion', 'L', 'L')
    API.new('GetProcessWorkingSetSize', 'LPP', 'B')
    API.new('GetStartupInfo', 'P', 'V')
    API.new('OpenJobObject', 'LIS', 'L')
    API.new('OpenProcess', 'LIL', 'L')
    API.new('QueryInformationJobObject', 'LLPLP', 'B')
    API.new('SetEnvironmentVariable', 'PP', 'B')
    API.new('SetInformationJobObject', 'LLPL', 'B')
    API.new('SetPriorityClass', 'LL', 'B')
    API.new('SetProcessAffinityMask', 'LL', 'B')
    API.new('SetProcessPriorityBoost', 'LB', 'B')
    API.new('SetProcessShutdownParameters', 'LL', 'B')
    API.new('SetProcessWorkingSetSize', 'LLL', 'B')
    API.new('TerminateJobObject', 'LL', 'B')
    API.new('TerminateProcess', 'LL', 'B')
    API.new('WaitForInputIdle', 'LL', 'L', 'user32')
    API.new('WTSEnumerateProcesses', 'LLLPP', 'B', 'wtsapi32')

    begin
      API.new('GetProcessId', 'L', 'L')
      API.new('GetProcessHandleCount', 'LP', 'B')
      API.new('IsProcessInJob', 'LLP', 'B')
      API.new('IsWow64Process', 'LP', 'B')
    rescue Win32::API::LoadLibraryError
      # Windows XP or later
    end

    # Helper method to determine if you're on a 64 bit version of Windows
    def windows_64?
      bool = false

      if defined? IsWow64Process
        buf = 0.chr * 4
        if IsWow64Process(GetCurrentProcess(), buf)
          if buf.unpack('I')[0] == 1
            bool = true
          end
        end
      end

      bool
    end
  end
end
