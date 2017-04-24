# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_version

  def self.create_dll(dll_path = 'version')
    dll = DLL.new(dll_path, ApiConstants.manager)

    dll.add_function('GetFileVersionInfoA', 'BOOL',[
      ["PCHAR","lptstrFilename","in"],
      ["DWORD","dwHandle","in"],
      ["DWORD","dwLen","in"],
      # Ignore lpData out as we will pass in our
      # own memory address and use memread
      ["LPVOID","lpData","in"],
    ])

    dll.add_function('GetFileVersionInfoSizeA', 'DWORD',[
      ["PCHAR","lptstrFilename","in"],
      ["PDWORD","lpdwHandle","out"]
    ])

    dll.add_function('VerQueryValueA', 'BOOL',[
      ["LPVOID","pBlock","in"],
      ["PCHAR","lpSubBlock","in"],
      ["PDWORD","lplpBuffer","out"],
      ["PDWORD","puLen","out"]
    ])

    return dll
  end

end

end; end; end; end; end; end; end
