require 'socket'
require 'stringio'
require 'net/ssh/test/extensions'
require 'net/ssh/test/script'

module Net 
  module SSH 
    module Test

      # A mock socket implementation for use in testing. It implements the minimum
      # necessary interface for interacting with the rest of the Net::SSH::Test
      # system.
      class Socket < StringIO
        attr_reader :host, :port
    
        # The Net::SSH::Test::Script object in use by this socket. This is the
        # canonical script instance that should be used for any test depending on
        # this socket instance.
        attr_reader :script
    
        # Create a new test socket. This will also instantiate a new Net::SSH::Test::Script
        # and seed it with the necessary events to power the initialization of the
        # connection.
        def initialize
          extend(Net::SSH::Transport::PacketStream)
          super "SSH-2.0-Test\r\n"
    
          @script = Script.new
    
          script.sends(:kexinit)
          script.gets(:kexinit, 1, 2, 3, 4, "test", "ssh-rsa", "none", "none", "none", "none", "none", "none", "", "", false)
          script.sends(:newkeys)
          script.gets(:newkeys)
        end
    
        # This doesn't actually do anything, since we don't really care what gets
        # written.
        def write(data)
          # black hole, because we don't actually care about what gets written
        end
    
        # Allows the socket to also mimic a socket factory, simply returning
        # +self+.
        def open(host, port, options={})
          @host, @port = host, port
          self
        end
    
        # Returns a sockaddr struct for the port and host that were used when the
        # socket was instantiated.
        def getpeername
          ::Socket.sockaddr_in(port, host)
        end
    
        # Alias to #read, but never returns nil (returns an empty string instead).
        def recv(n)
          read(n) || ""
        end
    
        def readpartial(n)
          recv(n)
        end
        
      end

    end
  end
end
