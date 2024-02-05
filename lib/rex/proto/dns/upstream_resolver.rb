# -*- coding: binary -*-

module Rex
module Proto
module DNS
  class UpstreamResolver
    TYPE_SYSTEM = :system
    TYPE_DNS_SERVER = :dns_server
    TYPE_BLACKHOLE = :blackhole

    attr_reader :type, :destination, :socket_options
    def initialize(type, destination: nil, socket_options: {})
      @type = type
      @destination = destination
      @socket_options = socket_options
    end

    def to_s
      case type
      when TYPE_BLACKHOLE
        'blackhole'
      when TYPE_SYSTEM
        'system'
      else
        destination.to_s
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
