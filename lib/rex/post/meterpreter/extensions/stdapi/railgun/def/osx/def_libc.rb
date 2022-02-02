# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_osx_libc

  def self.create_library(constant_manager, library_path = 'libc.dylib')
    lib = Library.new(library_path, constant_manager)

    lib.add_function(
      'calloc',
      'LPVOID',
      [
        ['SIZE_T', 'nmemb', 'in'],
        ['SIZE_T', 'size', 'in']
      ],
      nil,
      'cdecl'
    )
    lib.add_function(
      'dlclose',
      'DWORD',
      [
        ['LPVOID', 'handle', 'in']
      ],
      nil,
      'cdecl'
    )
    lib.add_function(
      'dlopen',
      'LPVOID',
      [
        ['PCHAR', 'filename', 'in'],
        ['DWORD', 'flags', 'in']
      ],
      nil,
      'cdecl'
    )
    lib.add_function(
      'free',
      'VOID',
      [
        ['LPVOID', 'ptr', 'in']
      ],
      nil,
      'cdecl',
    )
    lib.add_function(
      'getpid',
      'DWORD',
      [],
      nil,
      'cdecl'
    )
    lib.add_function(
      'inet_ntop',
      'LPVOID',
      [
        ['DWORD', 'af', 'in'],
        ['PBLOB', 'src', 'in'],
        ['PBLOB', 'dst', 'out'],
        ['DWORD', 'size', 'in']
      ],
      nil,
      'cdecl'
    )
    lib.add_function(
      'inet_pton',
      'DWORD',
      [
        ['DWORD', 'af', 'in'],
        ['PBLOB', 'src', 'in'],
        ['PBLOB', 'dst', 'out']
      ],
      nil,
      'cdecl'
    )
    lib.add_function(
      'malloc',
      'LPVOID',
      [['SIZE_T', 'size', 'in']],
      nil,
      'cdecl'
    )
    lib.add_function(
      'mmap',
      'LPVOID',
      [
        ['LPVOID', 'addr', 'in'],
        ['SIZE_T', 'length', 'in'],
        ['DWORD', 'prot', 'in'],
        ['DWORD', 'flags', 'in'],
        ['DWORD', 'fd', 'in'],
        ['SIZE_T', 'offset', 'in']
      ],
      nil,
      'cdecl'
    )
    lib.add_function(
      'mprotect',
      'DWORD',
      [
        ['LPVOID', 'addr', 'in'],
        ['SIZE_T', 'length', 'in'],
        ['DWORD', 'prot', 'in']
      ],
      nil,
      'cdecl'
    )
    lib.add_function(
      'munmap',
      'DWORD',
      [
        ['LPVOID', 'addr', 'in'],
        ['SIZE_T', 'length', 'in']
      ],
      nil,
      'cdecl'
    )
    lib.add_function(
      'strcat',
      'LPVOID',
      [
        ['PCHAR', 'to', 'inout'],
        ['PCHAR', 'from', 'in']
      ],
      nil,
      'cdecl'
    )
    return lib
  end

end

end; end; end; end; end; end; end
