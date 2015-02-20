# -*- coding: binary -*-
require 'rex/socket'
require 'rex/socket/tcp_server'
require 'rex/io/stream_server'

###
#
# This class provides methods for interacting with an SSL wrapped TCP server.  It
# implements the StreamServer IO interface.
#
###
module Rex::Socket::SslTcpServer

  @@loaded_openssl = false

  begin
    require 'openssl'
    @@loaded_openssl = true
    require 'openssl/nonblock'
  rescue ::Exception
  end

  include Rex::Socket::TcpServer

  ##
  #
  # Factory
  #
  ##

  def self.create(hash = {})
    hash['Proto']  = 'tcp'
    hash['Server'] = true
    hash['SSL']    = true
    self.create_param(Rex::Socket::Parameters.from_hash(hash))
  end

  #
  # Wrapper around the base class' creation method that automatically sets
  # the parameter's protocol to TCP and sets the server flag to true.
  #
  def self.create_param(param)
    param.proto  = 'tcp'
    param.server = true
    param.ssl    = true
    Rex::Socket.create_param(param)
  end

  def initsock(params = nil)
    raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
    self.sslctx  = makessl(params)
    super
  end

  # (see TcpServer#accept)
  def accept(opts = {})
    sock = super()
    return if not sock

    begin
      ssl = OpenSSL::SSL::SSLSocket.new(sock, self.sslctx)

      if not allow_nonblock?(ssl)
        ssl.accept
      else
        begin
          ssl.accept_nonblock

        # Ruby 1.8.7 and 1.9.0/1.9.1 uses a standard Errno
        rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
            IO::select(nil, nil, nil, 0.10)
            retry

        # Ruby 1.9.2+ uses IO::WaitReadable/IO::WaitWritable
        rescue ::Exception => e
          if ::IO.const_defined?('WaitReadable') and e.kind_of?(::IO::WaitReadable)
            IO::select( [ ssl ], nil, nil, 0.10 )
            retry
          end

          if ::IO.const_defined?('WaitWritable') and e.kind_of?(::IO::WaitWritable)
            IO::select( nil, [ ssl ], nil, 0.10 )
            retry
          end

          raise e
        end
      end

      sock.extend(Rex::Socket::SslTcp)
      sock.sslsock = ssl
      sock.sslctx  = self.sslctx

      return sock

    rescue ::OpenSSL::SSL::SSLError
      sock.close
      nil
    end
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
  # Shim for the ssl_parse_pem module method
  #
  def ssl_parse_pem(ssl_cert)
    Rex::Socket::SslTcpServer.ssl_parse_pem(ssl_cert)
  end

  #
  # Generate a realistic-looking but obstensibly fake SSL
  # certificate. This matches a typical "snakeoil" cert.
  #
  # @return [String, String, Array]
  def self.ssl_generate_certificate
    yr   = 24*3600*365
    vf   = Time.at(Time.now.to_i - rand(yr * 3) - yr)
    vt   = Time.at(vf.to_i + (10 * yr))
    cn   = Rex::Text.rand_text_alpha_lower(rand(8)+2)
    key  = OpenSSL::PKey::RSA.new(2048){ }
    cert = OpenSSL::X509::Certificate.new
    cert.version    = 2
    cert.serial     = (rand(0xFFFFFFFF) << 32) + rand(0xFFFFFFFF)
    cert.subject    = OpenSSL::X509::Name.new([["CN", cn]])
    cert.issuer     = OpenSSL::X509::Name.new([["CN", cn]])
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

  #
  # Shim for the ssl_generate_certificate module method
  #
  def ssl_generate_certificate
    Rex::Socket::SslTcpServer.ssl_generate_certificate
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

