# -*- coding: binary -*-

module Rex
module Proto
module DNS
  class UpstreamResolver
    TYPE_BLACK_HOLE = %s[black-hole]
    TYPE_DNS_SERVER = %s[dns-server]
    TYPE_STATIC = :static
    TYPE_SYSTEM = :system

    attr_reader :type, :destination, :socket_options
    def initialize(type, destination: nil, socket_options: {})
      @type = type
      @destination = destination
      @socket_options = socket_options
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
