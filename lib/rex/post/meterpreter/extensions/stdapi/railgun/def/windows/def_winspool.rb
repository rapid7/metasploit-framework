# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_windows_winspool

  def self.create_library(constant_manager, library_path = 'winspool.drv')
    dll = Library.new(library_path, constant_manager)

    dll.add_function('AddPrinterA', 'HANDLE',[
      ["PCHAR","pName","in"],
      ["DWORD","Level","in"],
      ["PBLOB","pPrinter","in"]
    ])

    dll.add_function('AddPrinterW', 'HANDLE',[
      ["PWCHAR","pName","in"],
      ["DWORD","Level","in"],
      ["PBLOB","pPrinter","in"]
    ])

    dll.add_function('EnumPrinterDriversA', 'BOOL',[
      ["PCHAR","pName","in"],
      ["PCHAR","pEnvironment","in"],
      ["DWORD","Level","in"],
      ["PBLOB","pDriverInfo","out"],
      ["DWORD","cbBuf","in"],
      ["PDWORD","pcbNeeded","out"],
      ["PDWORD","pcReturned","out"]
    ])

    dll.add_function('EnumPrinterDriversW', 'BOOL',[
      ["PWCHAR","pName","in"],
      ["PWCHAR","pEnvironment","in"],
      ["DWORD","Level","in"],
      ["PBLOB","pDriverInfo","out"],
      ["DWORD","cbBuf","in"],
      ["PDWORD","pcbNeeded","out"],
      ["PDWORD","pcReturned","out"]
    ])

    dll.add_function('EnumPrintersA', 'BOOL',[
      ["DWORD","Flags","in"],
      ["PCHAR","Name","in"],
      ["DWORD","Level","in"],
      ["PBLOB","pPrinterEnum","out"],
      ["DWORD","cbBuf","in"],
      ["PDWORD","pcbNeeded","out"],
      ["PDWORD","pcReturned","out"]
    ])

    dll.add_function('EnumPrintersW', 'BOOL',[
      ["DWORD","Flags","in"],
      ["PWCHAR","Name","in"],
      ["DWORD","Level","in"],
      ["PBLOB","pPrinterEnum","out"],
      ["DWORD","cbBuf","in"],
      ["PDWORD","pcbNeeded","out"],
      ["PDWORD","pcReturned","out"]
    ])

    dll.add_function('SetPrinterDataExA', 'DWORD',[
      ["HANDLE","hPrinter","in"],
      ["PCHAR","pKeyName","in"],
      ["PCHAR","pValueName","in"],
      ["DWORD","Type","in"],
      ["PBLOB","pData","in"],
      ["DWORD","cbData","in"]
    ])

    dll.add_function('SetPrinterDataExW', 'DWORD',[
      ["HANDLE","hPrinter","in"],
      ["PWCHAR","pKeyName","in"],
      ["PWCHAR","pValueName","in"],
      ["DWORD","Type","in"],
      ["PBLOB","pData","in"],
      ["DWORD","cbData","in"]
    ])

    dll.add_function('OpenPrinterA','BOOL',[
      ["PCHAR","pPrinterName","in"],
      ["PDWORD","phPrinter","out"],
      ["PBLOB","pDefault","in"]
    ])

    dll.add_function('OpenPrinterW','BOOL',[
      ["PWCHAR","pPrinterName","in"],
      ["PDWORD","phPrinter","out"],
      ["PBLOB","pDefault","in"]
    ])

    return dll
  end

end

end; end; end; end; end; end; end
