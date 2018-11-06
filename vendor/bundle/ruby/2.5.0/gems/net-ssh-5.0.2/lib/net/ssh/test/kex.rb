require 'openssl'

require 'net/ssh/errors'
require 'net/ssh/transport/algorithms'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/kex'

module Net 
  module SSH 
    module Test

      # An implementation of a key-exchange strategy specifically for unit tests.
      # (This strategy would never really work against a real SSH server--it makes
      # too many assumptions about the server's response.)
      #
      # This registers itself with the transport key-exchange system as the
      # "test" algorithm.
      class Kex
        include Net::SSH::Transport::Constants
    
        # Creates a new instance of the testing key-exchange algorithm with the
        # given arguments.
        def initialize(algorithms, connection, data)
          @connection = connection
        end
    
        # Exchange keys with the server. This returns a hash of constant values,
        # and does not actually exchange keys.
        def exchange_keys
          result = Net::SSH::Buffer.from(:byte, NEWKEYS)
          @connection.send_message(result)
    
          buffer = @connection.next_message
          raise Net::SSH::Exception, "expected NEWKEYS" unless buffer.type == NEWKEYS
    
          { session_id: "abc-xyz",
            server_key: OpenSSL::PKey::RSA.new(512),
            shared_secret: OpenSSL::BN.new("1234567890", 10),
            hashing_algorithm: OpenSSL::Digest::SHA1 }
        end
      end

    end
  end
end

Net::SSH::Transport::Algorithms::ALGORITHMS[:kex] << "test"
Net::SSH::Transport::Kex::MAP["test"] = Net::SSH::Test::Kex
