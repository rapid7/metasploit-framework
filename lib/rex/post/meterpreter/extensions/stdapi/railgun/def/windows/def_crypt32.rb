# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_windows_crypt32

  def self.create_library(constant_manager, library_path = 'crypt32')
    dll = Library.new(library_path, constant_manager)

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


