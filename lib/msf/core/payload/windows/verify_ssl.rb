# -*- coding: binary -*-

require 'msf/core'
require 'rex/socket/x509_certificate'

module Msf

###
#
# Implements SSL validation check options
#
###

module Payload::Windows::VerifySsl

  #
  # Get the SSL hash from the certificate, if required.
  #
  def get_ssl_cert_hash(verify_cert, handler_cert)
    unless verify_cert.to_s =~ /^(t|y|1)/i
      return nil
    end

    unless handler_cert
      raise ArgumentError, "Verifying SSL cert is enabled but no handler cert is configured"
    end

    hash = Rex::Socket::X509Certificate.get_cert_file_hash(handler_cert)
    print_status("Meterpreter will verify SSL Certificate with SHA1 hash #{hash.unpack("H*").first}")
    hash
  end

end

end

