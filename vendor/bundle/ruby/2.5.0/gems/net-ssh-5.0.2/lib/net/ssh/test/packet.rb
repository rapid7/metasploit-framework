require 'net/ssh/connection/constants'
require 'net/ssh/transport/constants'

module Net
  module SSH
    module Test

      # This is an abstract class, not to be instantiated directly, subclassed by
      # Net::SSH::Test::LocalPacket and Net::SSH::Test::RemotePacket. It implements
      # functionality common to those subclasses.
      #
      # These packets are not true packets, in that they don't represent what was
      # actually sent between the hosst; rather, they represent what was expected
      # to be sent, as dictated by the script (Net::SSH::Test::Script). Thus,
      # though they are defined with data elements, these data elements are used
      # to either validate data that was sent by the local host (Net::SSH::Test::LocalPacket)
      # or to mimic the sending of data by the remote host (Net::SSH::Test::RemotePacket).
      class Packet
        include Net::SSH::Transport::Constants
        include Net::SSH::Connection::Constants

        # Register a custom channel request. extra_parts is an array of types
        # of extra parameters
        def self.register_channel_request(request, extra_parts)
          @registered_requests ||= {}
          @registered_requests[request] = { extra_parts: extra_parts }
        end

        def self.registered_channel_requests(request)
          @registered_requests && @registered_requests[request]
        end

        # Ceate a new packet of the given +type+, and with +args+ being a list of
        # data elements in the order expected for packets of the given +type+
        # (see #types).
        def initialize(type, *args)
          @type = self.class.const_get(type.to_s.upcase)
          @data = args
        end

        # The default for +remote?+ is false. Subclasses should override as necessary.
        def remote?
          false
        end

        # The default for +local?+ is false. Subclasses should override as necessary.
        def local?
          false
        end

        # Instantiates the packets data elements. When the packet was first defined,
        # some elements may not have been fully realized, and were described as
        # Proc objects rather than atomic types. This invokes those Proc objects
        # and replaces them with their returned values. This allows for values
        # like Net::SSH::Test::Channel#remote_id to be used in scripts before
        # the remote_id is known (since it is only known after a channel has been
        # confirmed open).
        def instantiate!
          @data.map! { |i| i.respond_to?(:call) ? i.call : i }
        end

        # Returns an array of symbols describing the data elements for packets of
        # the same type as this packet. These types are used to either validate
        # sent packets (Net::SSH::Test::LocalPacket) or build received packets
        # (Net::SSH::Test::RemotePacket).
        #
        # Not all packet types are defined here. As new packet types are required
        # (e.g., a unit test needs to test that the remote host sent a packet that
        # is not implemented here), the description of that packet should be
        # added. Unsupported packet types will otherwise raise an exception.
        def types
          @types ||= case @type
                     when KEXINIT then
                       %i[long long long long
                          string string string string string string string string string string
                          bool]
                     when NEWKEYS then []
                     when CHANNEL_OPEN then %i[string long long long]
                     when CHANNEL_OPEN_CONFIRMATION then %i[long long long long]
                     when CHANNEL_DATA then %i[long string]
                     when CHANNEL_EXTENDED_DATA then %i[long long string]
                     when CHANNEL_EOF, CHANNEL_CLOSE, CHANNEL_SUCCESS, CHANNEL_FAILURE then [:long]
                     when CHANNEL_REQUEST
                       parts = %i[long string bool]
                       case @data[1]
                       when "exec", "subsystem","shell" then parts << :string
                       when "exit-status" then parts << :long
                       when "pty-req" then parts.concat(%i[string long long long long string])
                       when "env" then parts.contact(%i[string string])
                       else
                         request = Packet.registered_channel_requests(@data[1])
                         raise "don't know what to do about #{@data[1]} channel request" unless request
                         parts.concat(request[:extra_parts])
                       end
                     else raise "don't know how to parse packet type #{@type}"
                     end
        end
      end
    end
  end
end
