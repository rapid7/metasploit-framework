require 'windows/api'

module Windows
  module Service
    API.auto_namespace = 'Windows::Service'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    # SCM access rights
    SC_MANAGER_ALL_ACCESS         = 0xF003F
    SC_MANAGER_CREATE_SERVICE     = 0x0002
    SC_MANAGER_CONNECT            = 0x0001
    SC_MANAGER_ENUMERATE_SERVICE  = 0x0004
    SC_MANAGER_LOCK               = 0x0008
    SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020
    SC_MANAGER_QUERY_LOCK_STATUS  = 0x0010
    SC_STATUS_PROCESS_INFO        = 0
    SC_ENUM_PROCESS_INFO          = 0
    
    # Service control action types
    SC_ACTION_NONE        = 0
    SC_ACTION_RESTART     = 1
    SC_ACTION_REBOOT      = 2
    SC_ACTION_RUN_COMMAND = 3

    # Service access rights
    SERVICE_ALL_ACCESS            = 0xF01FF
    SERVICE_CHANGE_CONFIG         = 0x0002
    SERVICE_ENUMERATE_DEPENDENTS  = 0x0008
    SERVICE_INTERROGATE           = 0x0080
    SERVICE_PAUSE_CONTINUE        = 0x0040
    SERVICE_QUERY_CONFIG          = 0x0001
    SERVICE_QUERY_STATUS          = 0x0004
    SERVICE_START                 = 0x0010
    SERVICE_STOP                  = 0x0020
    SERVICE_USER_DEFINED_CONTROL  = 0x0100

    # Service types
    SERVICE_KERNEL_DRIVER       = 0x00000001
    SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002
    SERVICE_ADAPTER             = 0x00000004
    SERVICE_RECOGNIZER_DRIVER   = 0x00000008
    SERVICE_WIN32_OWN_PROCESS   = 0x00000010
    SERVICE_WIN32_SHARE_PROCESS = 0x00000020
    SERVICE_WIN32               = 0x00000030
    SERVICE_INTERACTIVE_PROCESS = 0x00000100
    SERVICE_DRIVER              = 0x0000000B
    SERVICE_TYPE_ALL            = 0x0000013F

    # Error control
    SERVICE_ERROR_IGNORE   = 0x00000000
    SERVICE_ERROR_NORMAL   = 0x00000001
    SERVICE_ERROR_SEVERE   = 0x00000002
    SERVICE_ERROR_CRITICAL = 0x00000003

    # Start types
    SERVICE_BOOT_START   = 0x00000000
    SERVICE_SYSTEM_START = 0x00000001
    SERVICE_AUTO_START   = 0x00000002
    SERVICE_DEMAND_START = 0x00000003
    SERVICE_DISABLED     = 0x00000004

    # Service control
    SERVICE_CONTROL_STOP           = 0x00000001
    SERVICE_CONTROL_PAUSE          = 0x00000002
    SERVICE_CONTROL_CONTINUE       = 0x00000003
    SERVICE_CONTROL_INTERROGATE    = 0x00000004
    SERVICE_CONTROL_PARAMCHANGE    = 0x00000006
    SERVICE_CONTROL_NETBINDADD     = 0x00000007
    SERVICE_CONTROL_NETBINDREMOVE  = 0x00000008
    SERVICE_CONTROL_NETBINDENABLE  = 0x00000009
    SERVICE_CONTROL_NETBINDDISABLE = 0x0000000A
    
    # Service controls accepted
    SERVICE_ACCEPT_STOP                  =  0x00000001
    SERVICE_ACCEPT_PAUSE_CONTINUE        =  0x00000002
    SERVICE_ACCEPT_SHUTDOWN              =  0x00000004
    SERVICE_ACCEPT_PARAMCHANGE           =  0x00000008
    SERVICE_ACCEPT_NETBINDCHANGE         =  0x00000010
    SERVICE_ACCEPT_HARDWAREPROFILECHANGE =  0x00000020
    SERVICE_ACCEPT_POWEREVENT            =  0x00000040
    SERVICE_ACCEPT_SESSIONCHANGE         =  0x00000080
    SERVICE_ACCEPT_PRESHUTDOWN           =  0x00000100

    # Service states
    SERVICE_ACTIVE    = 0x00000001
    SERVICE_INACTIVE  = 0x00000002
    SERVICE_STATE_ALL = 0x00000003
    
    # Service current states
    SERVICE_STOPPED          = 0x00000001
    SERVICE_START_PENDING    = 0x00000002
    SERVICE_STOP_PENDING     = 0x00000003
    SERVICE_RUNNING          = 0x00000004
    SERVICE_CONTINUE_PENDING = 0x00000005
    SERVICE_PAUSE_PENDING    = 0x00000006
    SERVICE_PAUSED           = 0x00000007
    
    # Info levels
    SERVICE_CONFIG_DESCRIPTION              = 1
    SERVICE_CONFIG_FAILURE_ACTIONS          = 2
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO  = 3
    SERVICE_CONFIG_FAILURE_ACTIONS_FLAG     = 4
    SERVICE_CONFIG_SERVICE_SID_INFO         = 5
    SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 6
    SERVICE_CONFIG_PRESHUTDOWN_INFO         = 7
    
    # Configuration
    SERVICE_NO_CHANGE = 0xffffffff
    
    API.new('ChangeServiceConfig', 'LLLLPPPPPPP', 'B', 'advapi32')
    API.new('ChangeServiceConfig2', 'LLP', 'B', 'advapi32')
    API.new('CloseServiceHandle', 'L', 'B', 'advapi32')
    API.new('ControlService', 'LLP', 'B', 'advapi32')
    API.new('CreateService', 'LPPLLLLPPPPPP', 'L', 'advapi32')
    API.new('DeleteService', 'L', 'B', 'advapi32')
    API.new('EnumDependentServices', 'LLPLPP', 'B', 'advapi32')
    API.new('EnumServicesStatus', 'LLLPLPPP', 'B', 'advapi32')
    API.new('EnumServicesStatusEx', 'LLLLPLPPPP', 'B', 'advapi32')
    API.new('GetServiceDisplayName', 'LPPP', 'B', 'advapi32')
    API.new('GetServiceKeyName', 'LPPP', 'B', 'advapi32')
    API.new('LockServiceDatabase', 'L', 'L', 'advapi32')
    API.new('NotifyBootConfigStatus', 'I', 'B', 'advapi32')
    API.new('OpenSCManager', 'PPL', 'L', 'advapi32')
    API.new('OpenService', 'LPL', 'L', 'advapi32')
    API.new('QueryServiceConfig', 'LPLP', 'B', 'advapi32')
    API.new('QueryServiceConfig2', 'LLPLP', 'B', 'advapi32')
    API.new('QueryServiceLockStatus', 'LPLP', 'B', 'advapi32')
    API.new('QueryServiceStatus', 'LP', 'B', 'advapi32')
    API.new('QueryServiceStatusEx', 'LLPLP', 'B', 'advapi32')
    API.new('RegisterServiceCtrlHandler', 'PK', 'L', 'advapi32')
    API.new('RegisterServiceCtrlHandlerEx', 'PKP', 'L', 'advapi32')
    API.new('SetServiceBits', 'LLII', 'B', 'advapi32')
    API.new('SetServiceStatus', 'LP', 'B', 'advapi32')
    API.new('StartService', 'LLP', 'B', 'advapi32')
    API.new('StartServiceCtrlDispatcher', 'P', 'B', 'advapi32')
    API.new('UnlockServiceDatabase', 'L', 'B', 'advapi32')
  end
end
