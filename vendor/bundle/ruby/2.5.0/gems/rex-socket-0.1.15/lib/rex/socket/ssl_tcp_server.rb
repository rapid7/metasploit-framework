# -*- coding: binary -*-
require 'rex/socket'
require 'rex/socket/ssl'
require 'rex/socket/tcp_server'
require 'rex/io/stream_server'

###
#
# This class provides methods for interacting with an SSL wrapped TCP server.  It
# implements the StreamServer IO interface.
#
###
module Rex::Socket::SslTcpServer

  include Rex::Socket::Ssl
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

    if params && params.sslctx && params.sslctx.kind_of?(OpenSSL::SSL::SSLContext)
      self.sslctx = params.sslctx
    else
      self.sslctx  = makessl(params)
    end

    super
  end

  # (see TcpServer#accept)
  def accept(opts = {})
    sock = super()
    return if not sock

    begin
      ssl = OpenSSL::SSL::SSLSocket.new(sock, self.sslctx)

      if not allow_nonblock?(ssl)
        begin
          Timeout::timeout(3.5) {
            ssl.accept
          }
        rescue ::Timeout::Error => e
          sock.close
          raise ::OpenSSL::SSL::SSLError
        end
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

end

