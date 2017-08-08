# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_windows_psapi

  def self.create_library(constant_manager, library_path = 'psapi')
    dll = Library.new(library_path, constant_manager)

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
