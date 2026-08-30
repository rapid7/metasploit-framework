# -*- coding: binary -*-

module Rex
module Proto
module DNS
  ##
  # This represents a single upstream DNS resolver target of one of the predefined types.
  ##
  class UpstreamResolver
    module Type
      BLACK_HOLE = :"black-hole"
      DNS_SERVER = :"dns-server"
      STATIC = :static
      SYSTEM = :system
    end

    attr_reader :type, :destination, :socket_options

    # @param [Symbol] type The resolver type.
    # @param [String] destination An optional destination, as used by some resolver types.
    # @param [Hash] socket_options Options to use for sockets when connecting to the destination, as used by some
    #   resolver types.
    def initialize(type, destination: nil, socket_options: {})
      @type = type
      @destination = destination
      @socket_options = socket_options
    end

    # Initialize a new black-hole resolver.
    def self.create_black_hole
      self.new(Type::BLACK_HOLE)
    end

    # Initialize a new dns-server resolver.
    #
    # @param [String] destination The IP address of the upstream DNS server.
    # @param [Hash] socket_options Options to use when connecting to the upstream DNS server.
    def self.create_dns_server(destination, socket_options: {})
      self.new(
        Type::DNS_SERVER,
        destination: destination,
        socket_options: socket_options
      )
    end

    # Initialize a new static resolver.
    def self.create_static
      self.new(Type::STATIC)
    end

    # Initialize a new system resolver.
    def self.create_system
      self.new(Type::SYSTEM)
    end

    def to_s
      if type == Type::DNS_SERVER
        destination.to_s
      else
        type.to_s
      end
    end

   def eql?(other)
      return false unless other.is_a?(self.class)
      return false unless other.type == type
      return false unless other.destination == destination
      return false unless other.socket_options == socket_options
      true
    end

    alias == eql?
  end
end
end
end
