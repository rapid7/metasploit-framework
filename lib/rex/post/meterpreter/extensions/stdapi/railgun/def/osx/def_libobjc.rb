# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_osx_libobjc

  def self.create_library(constant_manager, library_path = 'libobjc.dylib')
    lib = Library.new(library_path, constant_manager)

    # https://developer.apple.com/documentation/objectivec/1418952-objc_getclass?language=objc
    lib.add_function(
      'objc_getClass',
      'LPVOID',
      [
        ['PCHAR', 'name', 'in']
      ],
      nil,
      'cdecl'
    )

    # https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend?language=objc
    lib.add_function(
      'objc_msgSend',
      'LPVOID',
      [
        ['LPVOID', 'self', 'in'],
        ['LPVOID', 'op', 'in']
      ],
      nil,
      'cdecl'
    )

    # https://developer.apple.com/documentation/objectivec/1418557-sel_registername?language=objc
    lib.add_function(
      'sel_registerName',
      'LPVOID',
      [
        ['PCHAR', 'str', 'in']
      ],
      nil,
      'cdecl'
    )

    return lib
  end

end

end; end; end; end; end; end; end
