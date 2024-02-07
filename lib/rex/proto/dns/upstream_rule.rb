# -*- coding: binary -*-

require 'json'
require 'rex/socket'

module Rex
module Proto
module DNS
  class UpstreamRule

    attr_reader :wildcard, :resolvers, :comm
    def initialize(wildcard: '*', resolvers: [], comm: nil)
      ::ArgumentError.new("Invalid wildcard text: #{wildcard}") unless self.class.valid_wildcard?(wildcard)
      @wildcard = wildcard
      socket_options = {}
      socket_options['Comm'] = comm unless comm.nil?
      @resolvers = resolvers.map do |resolver|
        if resolver.is_a?(String) && !Rex::Socket.is_ip_addr?(resolver)
          resolver = resolver.downcase.to_sym
        end

        case resolver
        when UpstreamResolver
          resolver
        when UpstreamResolver::TYPE_BLACK_HOLE
          UpstreamResolver.new_black_hole
        when UpstreamResolver::TYPE_STATIC
          UpstreamResolver.new_static
        when UpstreamResolver::TYPE_SYSTEM
          UpstreamResolver.new_system
        else
          if Rex::Socket.is_ip_addr?(resolver)
            UpstreamResolver.new_dns_server(resolver, socket_options: socket_options)
          else
            raise ::ArgumentError.new("Invalid upstream DNS resolver: #{resolver}")
          end
        end
      end
      @comm = comm
    end

    def self.valid_resolver?(resolver)
      return true if Rex::Socket.is_ip_addr?(resolver)

      resolver = resolver.downcase.to_sym
      [
        UpstreamResolver::TYPE_BLACK_HOLE,
        UpstreamResolver::TYPE_STATIC,
        UpstreamResolver::TYPE_SYSTEM
      ].include?(resolver)
    end

    def self.valid_wildcard?(wildcard)
      wildcard == '*' || wildcard =~ /^(\*\.)?([a-z\d][a-z\d-]*[a-z\d]\.)+[a-z]+$/
    end

    def matches_name?(name)
      if wildcard == '*'
        true
      elsif wildcard.start_with?('*.')
        name.downcase.end_with?(wildcard[1..-1].downcase)
      else
        name.casecmp?(wildcard)
      end
    end

    def eql?(other)
      return false unless other.is_a?(self.class)
      return false unless other.wildcard == wildcard
      return false unless other.resolvers == resolvers
      return false unless other.comm == comm
      true
    end

    alias == eql?
  end
end
end
end
