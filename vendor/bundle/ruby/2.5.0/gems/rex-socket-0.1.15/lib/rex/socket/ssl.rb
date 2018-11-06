# -*- coding: binary -*-
require 'rex/socket/x509_certificate'
require 'timeout'
require 'openssl'

###
#
# This class provides methods for interacting with an SSL wrapped TCP server.  It
# implements the StreamServer IO interface.
#
###
module Rex::Socket::Ssl

  module CertProvider

    def self.ssl_generate_subject
      st  = Rex::Text.rand_state
      loc = Rex::Text.rand_name.capitalize
      org = Rex::Text.rand_name.capitalize
      cn  = Rex::Text.rand_hostname
      "/C=US/ST=#{st}/L=#{loc}/O=#{org}/CN=#{cn}"
    end

    def self.ssl_generate_issuer
      org = Rex::Text.rand_name.capitalize
      cn  = Rex::Text.rand_name.capitalize + " " + Rex::Text.rand_name.capitalize
      "/C=US/O=#{org}/CN=#{cn}"
    end

    #
    # Generate a realistic-looking but obstensibly fake SSL
    # certificate. This matches a typical "snakeoil" cert.
    #
    # @return [String, String, Array]
    def self.ssl_generate_certificate
      yr      = 24*3600*365
      vf      = Time.at(Time.now.to_i - rand(yr * 3) - yr)
      vt      = Time.at(vf.to_i + (rand(9)+1) * yr)
      subject = ssl_generate_subject
      issuer  = ssl_generate_issuer
      key     = OpenSSL::PKey::RSA.new(2048){ }
      cert    = OpenSSL::X509::Certificate.new
      cert.version    = 2
      cert.serial     = (rand(0xFFFFFFFF) << 32) + rand(0xFFFFFFFF)
      cert.subject    = OpenSSL::X509::Name.parse(subject)
      cert.issuer     = OpenSSL::X509::Name.parse(issuer)
      cert.not_before = vf
      cert.not_after  = vt
      cert.public_key = key.public_key

      ef = OpenSSL::X509::ExtensionFactory.new(nil,cert)
      cert.extensions = [
        ef.create_extension("basicConstraints","CA:FALSE")
      ]
      ef.issuer_certificate = cert

      cert.sign(key, OpenSSL::Digest::SHA256.new)

      [key, cert, nil]
    end
  end

  # This defines the global certificate provider for all consumers of the mixin
  # Beware that altering this at runtime in one consumer will affect all others
  # Providers must expose at least the class methods given above accepting the
  # same calling convention.
  @@cert_provider = Rex::Socket::Ssl::CertProvider

  def self.cert_provider=(val)
    @@cert_provider = val
  end

  #
  # Parse a certificate in unified PEM format that contains a private key and
  # one or more certificates. The first certificate is the primary, while any
  # additional certificates are treated as intermediary certificates. This emulates
  # the behavior of web servers like nginx.
  #
  # @param [String] ssl_cert
  # @return [String, String, Array]
  def self.ssl_parse_pem(ssl_cert)
    Rex::Socket::X509Certificate.parse_pem(ssl_cert)
  end

  def self.ssl_generate_subject
    @@cert_provider.ssl_generate_subject
  end

  def self.ssl_generate_issuer
    @@cert_provider.ssl_generate_issuer
  end

  def self.ssl_generate_certificate
    @@cert_provider.ssl_generate_certificate
  end

  #
  # Shim for the ssl_parse_pem module method
  #
  def ssl_parse_pem(ssl_cert)
    Rex::Socket::Ssl.ssl_parse_pem(ssl_cert)
  end

  #
  # Shim for the ssl_generate_certificate module method
  #
  def ssl_generate_certificate
    Rex::Socket::Ssl.ssl_generate_certificate
  end

  #
  # Create a new ssl context.  If +ssl_cert+ is not given, generates a new
  # key and a leaf certificate with random values.
  #
  # @param [Rex::Socket::Parameters] params
  # @return [::OpenSSL::SSL::SSLContext]
  def makessl(params)

    if params.ssl_cert
      key, cert, chain = ssl_parse_pem(params.ssl_cert)
    else
      key, cert, chain = ssl_generate_certificate
    end

    ctx = OpenSSL::SSL::SSLContext.new()
    ctx.key = key
    ctx.cert = cert
    ctx.extra_chain_cert = chain
    ctx.options = 0

    if params.ssl_cipher
      ctx.ciphers = params.ssl_cipher
    end

    # Older versions of OpenSSL do not export the OP_NO_COMPRESSION symbol
    if defined?(OpenSSL::SSL::OP_NO_COMPRESSION)
      # enable/disable the SSL/TLS-level compression
      if params.ssl_compression
        ctx.options &= ~OpenSSL::SSL::OP_NO_COMPRESSION
      else
        ctx.options |= OpenSSL::SSL::OP_NO_COMPRESSION
      end
    end

    ctx.session_id_context = Rex::Text.rand_text(16)

    return ctx
  end

  #
  # This flag determines whether to use the non-blocking openssl
  # API calls when they are available. This is still buggy on
  # Linux/Mac OS X, but is required on Windows
  #
  def allow_nonblock?(sock=self.sock)
    avail = sock.respond_to?(:accept_nonblock)
    if avail and Rex::Compat.is_windows
      return true
    end
    false
  end

  attr_accessor :sslctx
end
