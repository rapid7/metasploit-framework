# -*- coding: binary -*-

module Rex
module Proto
module DNS
  ##
  # This represents a single upstream DNS resolver target of one of the predefined types.
  ##
  class UpstreamResolver
    TYPE_BLACK_HOLE = %s[black-hole]
    TYPE_DNS_SERVER = %s[dns-server]
    TYPE_STATIC = :static
    TYPE_SYSTEM = :system

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
    def self.new_black_hole
      self.new(TYPE_BLACK_HOLE)
    end

    # Initialize a new dns-server resolver.
    #
    # @param [String] destination The IP address of the upstream DNS server.
    # @param [Hash] socket_options Options to use when connecting to the upstream DNS server.
    def self.new_dns_server(destination, socket_options: {})
      self.new(
        TYPE_DNS_SERVER,
        destination: destination,
        socket_options: socket_options
      )
    end

    # Initialize a new static resolver.
    def self.new_static
      self.new(TYPE_STATIC)
    end

    # Initialize a new system resolver.
    def self.new_system
      self.new(TYPE_SYSTEM)
    end

    def to_s
      if type == TYPE_DNS_SERVER
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
