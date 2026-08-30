# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_windows_dbghelp

  def self.create_library(constant_manager, library_path = 'dbghelp')
    dll = Library.new(library_path, constant_manager)

    dll.add_function('MiniDumpWriteDump', 'BOOL',[
      ["HANDLE","hProcess","in"],
      ["DWORD","ProcessId","in"],
      ["HANDLE","hFile","in"],
      ["DWORD","DumpType","in"],
      ["PBLOB","ExceptionParam","in"],
      ["PBLOB","UserStreamParam","in"],
      ["PBLOB","CallbackParam","in"],
      ])

    return dll
  end

end

end; end; end; end; end; end; end
