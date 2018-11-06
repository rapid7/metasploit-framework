require 'net/ssh/packet'
require 'net/ssh/test/packet'

module Net
  module SSH
    module Test

      # This is a specialization of Net::SSH::Test::Packet for representing mock
      # packets that are sent from the local (client) host. These are created
      # automatically by Net::SSH::Test::Script and Net::SSH::Test::Channel by any
      # of the sends_* methods.
      class LocalPacket < Packet
        attr_reader :init

        # Extend the default Net::SSH::Test::Packet constructor to also accept an
        # optional block, which is used to finalize the initialization of the
        # packet when #process is first called.
        def initialize(type, *args, &block)
          super(type, *args)
          @init = block
        end

        # Returns +true+; this is a local packet.
        def local?
          true
        end

        # Called by Net::SSH::Test::Extensions::PacketStream#test_enqueue_packet
        # to mimic remote processing of a locally-sent packet. It compares the
        # packet it was given with the contents of this LocalPacket's data, to see
        # if what was sent matches what was scripted. If it differs in any way,
        # an exception is raised.
        def process(packet)
          @init.call(Net::SSH::Packet.new(packet.to_s)) if @init
          type = packet.read_byte
          raise "expected #{@type}, but got #{type}" if @type != type

          @data.zip(types).each do |expected, _type|
            _type ||= case expected
                      when nil then break
                      when Numeric then :long
                      when String then :string
                      when TrueClass, FalseClass then :bool
                      end

            actual = packet.send("read_#{_type}")
            next if expected.nil?
            raise "expected #{_type} #{expected.inspect} but got #{actual.inspect}" unless expected == actual
          end
        end
      end

    end
  end
end
