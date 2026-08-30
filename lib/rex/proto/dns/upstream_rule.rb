# -*- coding: binary -*-

require 'json'
require 'rex/socket'

module Rex
module Proto
module DNS
  ##
  # This represents a configuration rule for how names should be resolved. It matches a single wildcard which acts as a
  # matching condition and maps it to 0 or more resolvers to use for lookups.
  ##
  class UpstreamRule

    attr_reader :wildcard, :resolvers, :comm
    # @param [String] wildcard The wildcard pattern to use for conditionally matching hostnames.
    # @param [Array] resolvers The resolvers to use when this rule is applied.
    # @param [Msf::Session::Comm] comm The communication channel to use when creating network connections.
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
        when UpstreamResolver::Type::BLACK_HOLE
          UpstreamResolver.create_black_hole
        when UpstreamResolver::Type::STATIC
          UpstreamResolver.create_static
        when UpstreamResolver::Type::SYSTEM
          UpstreamResolver.create_system
        else
          if Rex::Socket.is_ip_addr?(resolver)
            UpstreamResolver.create_dns_server(resolver, socket_options: socket_options)
          else
            raise ::ArgumentError.new("Invalid upstream DNS resolver: #{resolver}")
          end
        end
      end
      @comm = comm
    end

    # Check whether or not the defined resolver is valid.
    #
    # @param [String] resolver The resolver string to check.
    # @rtype Boolean
    def self.valid_resolver?(resolver)
      return true if Rex::Socket.is_ip_addr?(resolver)

      resolver = resolver.downcase.to_sym
      [
        UpstreamResolver::Type::BLACK_HOLE,
        UpstreamResolver::Type::STATIC,
        UpstreamResolver::Type::SYSTEM
      ].include?(resolver)
    end

    # Perform a spell check on resolver to suggest corrections.
    #
    # @param [String] resolver The resolver string to check.
    # @rtype [Nil, Array<String>] The suggestions if resolver is invalid.
    def self.spell_check_resolver(resolver)
      return nil if Rex::Socket.is_ip_addr?(resolver)

      suggestions = DidYouMean::SpellChecker.new(dictionary: [
        UpstreamResolver::Type::BLACK_HOLE,
        UpstreamResolver::Type::STATIC,
        UpstreamResolver::Type::SYSTEM
      ]).correct(resolver).map(&:to_s)
      return nil if suggestions.empty?

      suggestions
    end

    # Check whether or not the defined wildcard is a valid pattern.
    #
    # @param [String] wildcard The wildcard text to check.
    # @rtype Boolean
    def self.valid_wildcard?(wildcard)
      wildcard == '*' || wildcard =~ /^(\*\.)?([a-z\d][a-z\d-]*[a-z\d]\.)+[a-z]+$/
    end

    # Check whether or not the currently configured wildcard pattern will match all names.
    #
    # @rtype Boolean
    def matches_all?
      wildcard == '*'
    end

    # Check whether or not the specified name matches the currently configured wildcard pattern.
    #
    # @rtype Boolean
    def matches_name?(name)
      if matches_all?
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
