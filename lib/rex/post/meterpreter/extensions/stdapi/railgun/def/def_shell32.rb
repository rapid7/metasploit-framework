# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_shell32

  def self.create_dll(dll_path = 'shell32')
    dll = DLL.new(dll_path, ApiConstants.manager)

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
