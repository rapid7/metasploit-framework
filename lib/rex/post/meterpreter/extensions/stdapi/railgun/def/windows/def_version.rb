# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_windows_version

  def self.create_library(constant_manager, library_path = 'version')
    dll = Library.new(library_path, constant_manager)

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
      ["PULONG_PTR","lplpBuffer","out"],
      ["PDWORD","puLen","out"]
    ])

    return dll
  end

end

end; end; end; end; end; end; end
