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
  end
end
end
end
