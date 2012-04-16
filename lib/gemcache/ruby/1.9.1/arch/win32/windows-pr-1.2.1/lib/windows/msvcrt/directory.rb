require 'windows/api'

module Windows
  module MSVCRT
    module Directory
      API.auto_namespace = 'Windows::MSVCRT::Directory'
      API.auto_method    = true
      API.auto_constant  = true
      API.auto_unicode   = false 

      private

      API.new('_chdir', 'S', 'I', MSVCRT_DLL)
      API.new('_wchdir', 'S', 'I', MSVCRT_DLL)
      API.new('_chdrive', 'I', 'I', MSVCRT_DLL)
      API.new('_getcwd', 'PI', 'P', MSVCRT_DLL)
      API.new('_wgetcwd', 'PI', 'P', MSVCRT_DLL)
      API.new('_getdcwd', 'IPI', 'P', MSVCRT_DLL)
      API.new('_wgetdcwd', 'IPI', 'P', MSVCRT_DLL)
      API.new('_getdiskfree', 'IP', 'I', MSVCRT_DLL)
      API.new('_getdrive', 'V', 'I', MSVCRT_DLL)
      API.new('_getdrives', 'V', 'L', MSVCRT_DLL)
      API.new('_mkdir', 'S', 'I', MSVCRT_DLL)
      API.new('_wmkdir', 'S', 'I', MSVCRT_DLL)
      API.new('_rmdir', 'S', 'I', MSVCRT_DLL)
      API.new('_wrmdir', 'S', 'I', MSVCRT_DLL)
      API.new('_searchenv', 'SSP', 'V', MSVCRT_DLL)
      API.new('_wsearchenv', 'SSP', 'V', MSVCRT_DLL)
    end
  end
end
