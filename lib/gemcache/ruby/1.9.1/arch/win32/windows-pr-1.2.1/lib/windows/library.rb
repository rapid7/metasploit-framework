require 'windows/api'

module Windows
  module Library
    API.auto_namespace = 'Windows::Library'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    DLL_PROCESS_DETACH = 0
    DLL_PROCESS_ATTACH = 1
    DLL_THREAD_ATTACH  = 2
    DLL_THREAD_DETACH  = 3

    GET_MODULE_HANDLE_EX_FLAG_PIN                = 1
    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 2
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS       = 4

    DONT_RESOLVE_DLL_REFERENCES   = 0x00000001
    LOAD_LIBRARY_AS_DATAFILE      = 0x00000002
    LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
    LOAD_IGNORE_CODE_AUTHZ_LEVEL  = 0x00000010

    API.new('DisableThreadLibraryCalls', 'L', 'B')
    API.new('FreeLibrary', 'L', 'B')
    API.new('FreeLibraryAndExitThread', 'LL', 'V')
    API.new('GetModuleFileName', 'LPL', 'L')
    API.new('GetModuleHandle', 'P', 'L')
    API.new('GetProcAddress', 'LP', 'L')
    API.new('LoadLibrary', 'P', 'L')
    API.new('LoadLibraryEx', 'PLL', 'L')
    API.new('LoadModule', 'PP', 'L')

    begin
      API.new('GetDllDirectory', 'LP', 'L')
      API.new('GetModuleHandleEx', 'LPP', 'I')
      API.new('SetDllDirectory', 'P', 'I')
    rescue Win32::API::LoadLibraryError
      # Windows XP or later
    end
  end
end
