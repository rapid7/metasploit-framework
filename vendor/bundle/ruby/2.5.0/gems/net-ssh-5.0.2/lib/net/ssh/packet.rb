require 'net/ssh/buffer'
require 'net/ssh/transport/constants'
require 'net/ssh/authentication/constants'
require 'net/ssh/connection/constants'

module Net
  module SSH

    # A specialization of Buffer that knows the format of certain common
    # packet types. It auto-parses those packet types, and allows them to
    # be accessed via the #[] accessor.
    #
    #   data = some_channel_request_packet
    #   packet = Net::SSH::Packet.new(data)
    #
    #   p packet.type #-> 98 (CHANNEL_REQUEST)
    #   p packet[:request]
    #   p packet[:want_reply]
    #
    # This is used exclusively internally by Net::SSH, and unless you're doing
    # protocol-level manipulation or are extending Net::SSH in some way, you'll
    # never need to use this class directly.
    class Packet < Buffer
      @@types = {}

      # Register a new packet type that should be recognized and auto-parsed by
      # Net::SSH::Packet. Note that any packet type that is not preregistered
      # will not be autoparsed.
      #
      # The +pairs+ parameter must be either empty, or an array of two-element
      # tuples, where the first element of each tuple is the name of the field,
      # and the second is the type.
      #
      #   register DISCONNECT, [:reason_code, :long], [:description, :string], [:language, :string]
      def self.register(type, *pairs)
        @@types[type] = pairs
      end

      include Connection::Constants
      include Authentication::Constants
      include Transport::Constants

      #--
      # These are the recognized packet types. All other packet types will be
      # accepted, but not auto-parsed, requiring the client to parse the
      # fields using the methods provided by Net::SSH::Buffer.
      #++

      register DISCONNECT,                %i[reason_code long], %i[description string], %i[language string]
      register IGNORE,                    %i[data string]
      register UNIMPLEMENTED,             %i[number long]
      register DEBUG,                     %i[always_display bool], %i[message string], %i[language string]
      register SERVICE_ACCEPT,            %i[service_name string]
      register USERAUTH_BANNER,           %i[message string], %i[language string]
      register USERAUTH_FAILURE,          %i[authentications string], %i[partial_success bool]
      register GLOBAL_REQUEST,            %i[request_type string], %i[want_reply bool], %i[request_data buffer]
      register CHANNEL_OPEN,              %i[channel_type string], %i[remote_id long], %i[window_size long], %i[packet_size long]
      register CHANNEL_OPEN_CONFIRMATION, %i[local_id long], %i[remote_id long], %i[window_size long], %i[packet_size long]
      register CHANNEL_OPEN_FAILURE,      %i[local_id long], %i[reason_code long], %i[description string], %i[language string]
      register CHANNEL_WINDOW_ADJUST,     %i[local_id long], %i[extra_bytes long]
      register CHANNEL_DATA,              %i[local_id long], %i[data string]
      register CHANNEL_EXTENDED_DATA,     %i[local_id long], %i[data_type long], %i[data string]
      register CHANNEL_EOF,               %i[local_id long]
      register CHANNEL_CLOSE,             %i[local_id long]
      register CHANNEL_REQUEST,           %i[local_id long], %i[request string], %i[want_reply bool], %i[request_data buffer]
      register CHANNEL_SUCCESS,           %i[local_id long]
      register CHANNEL_FAILURE,           %i[local_id long]

      # The (integer) type of this packet.
      attr_reader :type

      # Create a new packet from the given payload. This will automatically
      # parse the packet if it is one that has been previously registered with
      # Packet.register; otherwise, the packet will need to be manually parsed
      # using the methods provided in the Net::SSH::Buffer superclass.
      def initialize(payload)
        @named_elements = {}
        super
        @type = read_byte
        instantiate!
      end

      # Access one of the auto-parsed fields by name. Raises an error if no
      # element by the given name exists.
      def [](name)
        name = name.to_sym
        raise ArgumentError, "no such element #{name}" unless @named_elements.key?(name)
        @named_elements[name]
      end

      private

      # Parse the packet's contents and assign the named elements, as described
      # by the registered format for the packet.
      def instantiate!
        (@@types[type] || []).each do |name, datatype|
          @named_elements[name.to_sym] = if datatype == :buffer
                                           remainder_as_buffer
                                         else
                                           send("read_#{datatype}")
                                         end
        end
      end
    end
  end
end
