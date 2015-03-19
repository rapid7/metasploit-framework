# -*- coding: binary -*-

require 'openssl'

module Rex
module Parser

###
#
# This class parses the contents of a PEM-encoded X509 certificate file containing
# a private key, a public key, and any appended glue certificates.
#
###
class X509Certificate

  #
  # Parse a certificate in unified PEM format that contains a private key and
  # one or more certificates. The first certificate is the primary, while any
  # additional certificates are treated as intermediary certificates. This emulates
  # the behavior of web servers like nginx.
  #
  # @param [String] ssl_cert
  # @return [String, String, Array]
  def self.parse_pem(ssl_cert)
    cert  = nil
    key   = nil
    chain = nil

    certs = []
    ssl_cert.scan(/-----BEGIN\s*[^\-]+-----+\r?\n[^\-]*-----END\s*[^\-]+-----\r?\n?/nm).each do |pem|
      if pem =~ /PRIVATE KEY/
        key = OpenSSL::PKey::RSA.new(pem)
      elsif pem =~ /CERTIFICATE/
        certs << OpenSSL::X509::Certificate.new(pem)
      end
    end

    cert = certs.shift
    if certs.length > 0
      chain = certs
    end

    [key, cert, chain]
  end

  #
  # Parse a certificate in unified PEM format from a file
  #
  # @param [String] ssl_cert_file
  # @return [String, String, Array]
  def self.parse_pem_file(ssl_cert_file)
    data = ''
    ::File.open(ssl_cert_file, 'rb') do |fd|
      data << fd.read(fd.stat.size)
    end
    parse_pem(data)
  end

end

end
end
