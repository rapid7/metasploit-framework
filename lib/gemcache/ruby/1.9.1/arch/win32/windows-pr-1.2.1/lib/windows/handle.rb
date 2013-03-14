require 'windows/api'

module Windows
  module Handle
    API.auto_namespace = 'Windows::Handle'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = false

    private

    INVALID_HANDLE_VALUE           = 0xFFFFFFFF
    HANDLE_FLAG_INHERIT            = 0x00000001
    HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x00000002

    API.new('CloseHandle', 'L', 'B')
    API.new('DuplicateHandle', 'LLLPLIL', 'B')
    API.new('GetHandleInformation', 'LL', 'B')
    API.new('SetHandleInformation', 'LLL', 'B')
    API.new('_get_osfhandle', 'I', 'L', MSVCRT_DLL)
    API.new('_open_osfhandle', 'LI', 'I', MSVCRT_DLL)
  end
end
