# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_libc

  def self.create_dll(constant_manager, dll_path = 'libc.so.6')
    dll = DLL.new(dll_path, constant_manager)

    dll.add_function(
      'calloc',
      'LPVOID',
      [
        ['SIZE_T', 'nmemb', 'in'],
        ['SIZE_T', 'size', 'in']
      ],
      nil,
      'cdecl'
    )
    dll.add_function(
      'free',
      'VOID',
      [
        ['LPVOID', 'ptr', 'in']
      ],
      nil,
      'cdecl',
    )
    dll.add_function(
      'getpid',
      'DWORD',
      [],
      nil,
      'cdecl'
    )
    dll.add_function(
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
    dll.add_function(
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
    dll.add_function(
      'malloc',
      'LPVOID',
      [['SIZE_T', 'size', 'in']],
      nil,
      'cdecl'
    )
    dll.add_function(
      'memfrob',
      'LPVOID',
      [
        ['PBLOB', 'mem', 'inout'],
        ['SIZE_T', 'length', 'in']
      ],
      nil,
      'cdecl'
    )
    dll.add_function(
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
    dll.add_function(
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
    dll.add_function(
      'munmap',
      'DWORD',
      [
        ['LPVOID', 'addr', 'in'],
        ['SIZE_T', 'length', 'in']
      ],
      nil,
      'cdecl'
    )
    return dll
  end

end

end; end; end; end; end; end; end
