require 'net/ssh/buffer'
require 'net/ssh/test/packet'

module Net 
  module SSH 
    module Test

      # This is a specialization of Net::SSH::Test::Packet for representing mock
      # packets that are received by the local (client) host. These are created
      # automatically by Net::SSH::Test::Script and Net::SSH::Test::Channel by any
      # of the gets_* methods.
      class RemotePacket < Packet
        # Returns +true+; this is a remote packet.
        def remote?
          true
        end
    
        # The #process method should only be called on Net::SSH::Test::LocalPacket
        # packets; if it is attempted on a remote packet, then it is an expectation
        # mismatch (a remote packet was received when a local packet was expected
        # to be sent). This will happen when either your test script
        # (Net::SSH::Test::Script) or your program are wrong.
        def process(packet)
          raise "received packet type #{packet.read_byte} and was not expecting any packet"
        end
    
        # Returns this remote packet as a string, suitable for parsing by 
        # Net::SSH::Transport::PacketStream and friends. When a remote packet is
        # received, this method is called and the result concatenated onto the
        # input buffer for the packet stream.
        def to_s
          @to_s ||= begin
            instantiate!
            string = Net::SSH::Buffer.from(:byte, @type, *types.zip(@data).flatten).to_s
            [string.length, string].pack("NA*")
          end
        end
      end

    end
  end
end