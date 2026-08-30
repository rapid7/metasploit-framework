# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_windows_shell32

  def self.create_library(constant_manager, library_path = 'shell32')
    dll = Library.new(library_path, constant_manager)

    dll.add_function('IsUserAnAdmin', 'BOOL', [
      ])

    dll.add_function('ShellExecuteA', 'DWORD',[
      ["DWORD","hwnd","in"],
      ["PCHAR","lpOperation","in"],
      ["PCHAR","lpFile","in"],
      ["PCHAR","lpParameters","in"],
      ["PCHAR","lpDirectory","in"],
      ["DWORD","nShowCmd","in"]
      ])

    return dll
  end

end

end; end; end; end; end; end; end
