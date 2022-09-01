# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_windows_spoolss

  def self.create_library(constant_manager, library_path = 'spoolss')
    dll = Library.new(library_path, constant_manager)

    dll.add_function('DeletePrinter', 'BOOL',[
      ["HANDLE","hPrinter","inout"]
    ])

    dll.add_function('ClosePrinter', 'BOOL',[
      ["HANDLE","hPrinter","in"]
    ])

    return dll
  end

end

end; end; end; end; end; end; end
