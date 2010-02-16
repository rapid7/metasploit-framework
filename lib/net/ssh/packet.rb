require 'net/ssh/buffer'
require 'net/ssh/transport/constants'
require 'net/ssh/authentication/constants'
require 'net/ssh/connection/constants'

module Net; module SSH

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

    include Transport::Constants, Authentication::Constants, Connection::Constants

    #--
    # These are the recognized packet types. All other packet types will be
    # accepted, but not auto-parsed, requiring the client to parse the
    # fields using the methods provided by Net::SSH::Buffer.
    #++

    register DISCONNECT,                [:reason_code, :long], [:description, :string], [:language, :string]
    register IGNORE,                    [:data, :string]
    register UNIMPLEMENTED,             [:number, :long]
    register DEBUG,                     [:always_display, :bool], [:message, :string], [:language, :string]
    register SERVICE_ACCEPT,            [:service_name, :string]
    register USERAUTH_BANNER,           [:message, :string], [:language, :string]
    register USERAUTH_FAILURE,          [:authentications, :string], [:partial_success, :bool]
    register GLOBAL_REQUEST,            [:request_type, :string], [:want_reply, :bool], [:request_data, :buffer]
    register CHANNEL_OPEN,              [:channel_type, :string], [:remote_id, :long], [:window_size, :long], [:packet_size, :long]
    register CHANNEL_OPEN_CONFIRMATION, [:local_id, :long], [:remote_id, :long], [:window_size, :long], [:packet_size, :long]
    register CHANNEL_OPEN_FAILURE,      [:local_id, :long], [:reason_code, :long], [:description, :string], [:language, :string]
    register CHANNEL_WINDOW_ADJUST,     [:local_id, :long], [:extra_bytes, :long]
    register CHANNEL_DATA,              [:local_id, :long], [:data, :string]
    register CHANNEL_EXTENDED_DATA,     [:local_id, :long], [:data_type, :long], [:data, :string]
    register CHANNEL_EOF,               [:local_id, :long]
    register CHANNEL_CLOSE,             [:local_id, :long]
    register CHANNEL_REQUEST,           [:local_id, :long], [:request, :string], [:want_reply, :bool], [:request_data, :buffer]
    register CHANNEL_SUCCESS,           [:local_id, :long]
    register CHANNEL_FAILURE,           [:local_id, :long]

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
end; end