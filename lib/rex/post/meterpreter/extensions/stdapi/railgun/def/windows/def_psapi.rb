# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_psapi

  def self.create_dll(constant_manager, dll_path = 'psapi')
    dll = DLL.new(dll_path, constant_manager)

    dll.add_function('EnumDeviceDrivers', 'BOOL',[
      %w(PBLOB lpImageBase out),
      %w(DWORD cb in),
      %w(PDWORD lpcbNeeded out)
    ])

    dll.add_function('GetDeviceDriverBaseNameA', 'DWORD', [
      %w(LPVOID ImageBase in),
      %w(PBLOB lpBaseName out),
      %w(DWORD nSize in)
    ])

    return dll
  end

end

end; end; end; end; end; end; end
