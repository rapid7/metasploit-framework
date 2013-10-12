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
    self.sslctx  = makessl(params.ssl_cert)
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
            IO::Rex.sleep(0.10)
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
  # Create a new ssl context.  If +ssl_cert+ is not given, generates a new
  # key and a leaf certificate with random values.
  #
  # @return [::OpenSSL::SSL::SSLContext]
  def makessl(ssl_cert=nil)

    if ssl_cert
      cert = OpenSSL::X509::Certificate.new(ssl_cert)
      key = OpenSSL::PKey::RSA.new(ssl_cert)
    else
      key = OpenSSL::PKey::RSA.new(1024){ }
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = rand(0xFFFFFFFF)
      # name = OpenSSL::X509::Name.new([["C","JP"],["O","TEST"],["CN","localhost"]])
      subject = OpenSSL::X509::Name.new([
          ["C","US"],
          ['ST', Rex::Text.rand_state()],
          ["L", Rex::Text.rand_text_alpha(rand(20) + 10)],
          ["O", Rex::Text.rand_text_alpha(rand(20) + 10)],
          ["CN", Rex::Text.rand_hostname],
        ])
      issuer = OpenSSL::X509::Name.new([
          ["C","US"],
          ['ST', Rex::Text.rand_state()],
          ["L", Rex::Text.rand_text_alpha(rand(20) + 10)],
          ["O", Rex::Text.rand_text_alpha(rand(20) + 10)],
          ["CN", Rex::Text.rand_hostname],
        ])

      cert.subject = subject
      cert.issuer = issuer
      cert.not_before = Time.now - (3600 * 365)
      cert.not_after = Time.now + (3600 * 365)
      cert.public_key = key.public_key
      ef = OpenSSL::X509::ExtensionFactory.new(nil,cert)
      cert.extensions = [
        ef.create_extension("basicConstraints","CA:FALSE"),
        ef.create_extension("subjectKeyIdentifier","hash"),
        ef.create_extension("extendedKeyUsage","serverAuth"),
        ef.create_extension("keyUsage","keyEncipherment,dataEncipherment,digitalSignature")
      ]
      ef.issuer_certificate = cert
      cert.add_extension ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
      cert.sign(key, OpenSSL::Digest::SHA1.new)
    end

    ctx = OpenSSL::SSL::SSLContext.new()
    ctx.key = key
    ctx.cert = cert

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

