# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_crypt32

  def self.create_dll(dll_path = 'crypt32')
    dll = DLL.new(dll_path, ApiConstants.manager)

    dll.add_function('CryptUnprotectData', 'BOOL', [
        ['PBLOB','pDataIn', 'in'],
        ['PWCHAR', 'szDataDescr', 'out'],
        ['PBLOB', 'pOptionalEntropy', 'in'],
        ['PDWORD', 'pvReserved', 'in'],
        ['PBLOB', 'pPromptStruct', 'in'],
        ['DWORD', 'dwFlags', 'in'],
        ['PBLOB', 'pDataOut', 'out']
      ])

    return dll
  end

end

end; end; end; end; end; end; end


