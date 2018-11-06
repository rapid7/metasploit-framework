require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/version'

module Net 
  module SSH 
    module Transport

      # Negotiates the SSH protocol version and trades information about server
      # and client. This is never used directly--it is always called by the
      # transport layer as part of the initialization process of the transport
      # layer.
      #
      # Note that this class also encapsulates the negotiated version, and acts as
      # the authoritative reference for any queries regarding the version in effect.
      class ServerVersion
        include Loggable
    
        # The SSH version string as reported by Net::SSH
        PROTO_VERSION = "SSH-2.0-Ruby/Net::SSH_#{Net::SSH::Version::CURRENT} #{RUBY_PLATFORM}"
    
        # Any header text sent by the server prior to sending the version.
        attr_reader :header
    
        # The version string reported by the server.
        attr_reader :version
    
        # Instantiates a new ServerVersion and immediately (and synchronously)
        # negotiates the SSH protocol in effect, using the given socket.
        def initialize(socket, logger, timeout = nil)
          @header = ""
          @version = nil
          @logger = logger
          negotiate!(socket, timeout)
        end
    
        private
    
        # Negotiates the SSH protocol to use, via the given socket. If the server
        # reports an incompatible SSH version (e.g., SSH1), this will raise an
        # exception.
        def negotiate!(socket, timeout)
          info { "negotiating protocol version" }
    
          debug { "local is `#{PROTO_VERSION}'" }
          socket.write "#{PROTO_VERSION}\r\n"
          socket.flush
    
          raise Net::SSH::ConnectionTimeout, "timeout during server version negotiating" if timeout && !IO.select([socket], nil, nil, timeout)
          loop do
            @version = ""
            loop do
              begin
                b = socket.readpartial(1)
                raise Net::SSH::Disconnect, "connection closed by remote host" if b.nil?
              rescue EOFError
                raise Net::SSH::Disconnect, "connection closed by remote host"
              end
              @version << b
              break if b == "\n"
            end
            break if @version.match(/^SSH-/)
            @header << @version
          end
    
          @version.chomp!
          debug { "remote is `#{@version}'" }
    
          raise Net::SSH::Exception, "incompatible SSH version `#{@version}'" unless @version.match(/^SSH-(1\.99|2\.0)-/)
    
          raise Net::SSH::ConnectionTimeout, "timeout during client version negotiating" if timeout && !IO.select(nil, [socket], nil, timeout)
        end
      end
    end
  end
end
