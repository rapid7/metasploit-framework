# -*- coding: binary -*-

module Msf

###
#
# Basic send_uuid stub for OSX ARCH_X64 payloads
#
###

module Payload::Osx::SendUUID_x64

  #
  # Generate assembly code that writes the UUID to the socket.
  #
  def asm_send_uuid(uuid=nil)
    uuid ||= generate_payload_uuid
    uuid_raw = uuid.to_raw

    asm =%Q^
      send_uuid:
        call get_uuid_address     ; put uuid buffer on the stack
        db #{raw_to_db(uuid_raw)} ; UUID
      get_uuid_address:
        pop rsi                   ; UUID address
        push #{uuid_raw.length}   ; length of the UUID
        pop rdx
        push 0x2000085
        pop rax
        syscall                   ; sendto(sockfd, addr, length)
    ^

    asm
  end

end

end

