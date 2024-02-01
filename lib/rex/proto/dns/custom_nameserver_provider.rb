require 'rex/proto/dns/upstream_resolver'

module Rex
module Proto
module DNS

  ##
  # Provides a DNS resolver the ability to use different nameservers
  # for different requests, based on the domain being queried.
  ##
  module CustomNameserverProvider
    CONFIG_KEY = 'framework/dns'

    #
    # A Comm implementation that always reports as dead, so should never
    # be used. This is used to prevent DNS leaks of saved DNS rules that
    # were attached to a specific channel.
    ##
    class CommSink
      include Msf::Session::Comm
      def alive?
        false
      end

      def supports_udp?
        # It won't be used anyway, so let's just say we support it
        true
      end

      def sid
        'previous MSF session'
      end
    end

    def init
      @upstream_entries = []
      self.next_id = 0
    end

    #
    # Save the custom settings to the MSF config file
    #
    def save_config
      new_config = {}
      @upstream_entries.each do |entry|
        key = entry[:id].to_s
        val = [entry[:wildcard_rule],
               entry[:servers].join(','),
               (!entry[:comm].nil?).to_s
              ].join(';')
        new_config[key] = val
      end

      Msf::Config.save(CONFIG_KEY => new_config)
    end

    #
    # Load the custom settings from the MSF config file
    #
    def load_config
      config = Msf::Config.load

      with_rules = []
      next_id = 0

      dns_settings = config.fetch(CONFIG_KEY, {}).each do |name, value|
        id = name.to_i
        wildcard_rule, dns_servers, uses_comm = value.split(';')
        wildcard_rule = '*' if wildcard_rule.blank?
        dns_servers = dns_servers.split(',')

        raise Rex::Proto::DNS::Exceptions::ConfigError.new('DNS parsing failed: Comm must be true or false') unless ['true','false'].include?(uses_comm)
        raise Rex::Proto::DNS::Exceptions::ConfigError.new('Invalid DNS config: Invalid DNS server') unless dns_servers.all? {|dns_server| Rex::Socket.is_ip_addr?(dns_server)}
        raise Rex::Proto::DNS::Exceptions::ConfigError.new('Invalid DNS config: Invalid rule') unless valid_rule?(wildcard_rule)

        comm = uses_comm == 'true' ? CommSink.new : nil
        with_rules <<  {
          :wildcard_rule => wildcard_rule,
          :servers => dns_servers,
          :comm => comm,
          :id => id
        }

        next_id = [id + 1, next_id].max
      end

      # Now that config has successfully read, update the global values
      @upstream_entries = with_rules
      self.next_id = next_id
    end

    # Add a custom nameserver entry to the custom provider
    # @param dns_servers [Array<String>] The list of IP addresses that would be used for this custom rule
    # @param comm [Msf::Session::Comm] The communication channel to be used for these DNS requests
    #  @param wildcard_rule String The wildcard rule to match a DNS request against
    def add_nameserver(dns_servers, comm: nil, wildcard_rule: '*')
      dns_servers = [dns_servers] if dns_servers.is_a?(String) # coerce into an array of strings
      if (dns_server = dns_servers.find {|dns_server| !Rex::Socket.is_ip_addr?(dns_server)})
        raise ::ArgumentError.new("Invalid DNS server: #{dns_server}")
      end

      raise ::ArgumentError.new("Invalid rule: #{wildcard_rule}") unless valid_rule?(wildcard_rule)

      @upstream_entries << {
        :wildcard_rule => wildcard_rule,
        :type => UpstreamResolver::TYPE_DNS_SERVER,
        :servers => dns_servers,
        :comm => comm,
        :id => self.next_id
      }
      self.next_id += 1
    end

    #
    # Remove entries with the given IDs
    # Ignore entries that are not found
    # @param ids [Array<Integer>] The IDs to removed
    # @return [Array<Hash>] The removed entries
    #
    def remove_ids(ids)
      removed= []
      ids.each do |id|
        removed_with, remaining_with = @upstream_entries.partition {|entry| entry[:id] == id}
        @upstream_entries.replace(remaining_with)
        removed.concat(removed_with)
      end

      removed
    end

    def purge
      init
    end

    # The nameservers that match the given packet
    # @param packet [Dnsruby::Message] The DNS packet to be sent
    # @raise [ResolveError] If the packet contains multiple questions, which would end up sending to a different set of nameservers
    # @return [Array<Array>] A list of nameservers, each with Rex::Socket options
    #
    def upstream_resolvers_for_packet(packet)
      unless feature_set.enabled?(Msf::FeatureManager::DNS_FEATURE)
        return super
      end
      # Leaky abstraction: a packet could have multiple question entries,
      # and each of these could have different nameservers, or travel via
      # different comm channels. We can't allow DNS leaks, so for now, we
      # will throw an error here.
      results_from_all_questions = []
      packet.question.each do |question|
        name = question.qname.to_s
        upstream_resolvers = []

        self.upstream_entries.each do |entry|
          next unless matches(name, entry[:wildcard_rule])

          socket_options = {}
          socket_options['Comm'] = entry[:comm] unless entry[:comm].nil?
          entry[:servers].each do |server|
            upstream_resolvers.append(UpstreamResolver.new(
              UpstreamResolver::TYPE_DNS_SERVER,
              destination: server,
              socket_options: socket_options
            ))
          end
          break
        end

        if upstream_resolvers.empty?
          # Fall back to default nameservers
          upstream_resolvers = super
        end
        results_from_all_questions << upstream_resolvers.uniq
      end
      results_from_all_questions.uniq!
      if results_from_all_questions.size != 1
        raise ResolverError.new('Inconsistent nameserver entries attempted to be sent in the one packet')
      end

      results_from_all_questions[0]
    end

    def self.extended(mod)
      mod.init
    end

    def set_framework(framework)
      self.feature_set = framework.features
    end

    def upstream_entries
      entries = @upstream_entries.dup
      entries << { id: '', wildcard_rule: '*', servers: self.nameservers }
      entries
    end

    private
    #
    # Is the given wildcard DNS entry valid?
    #
    def valid_rule?(rule)
      rule == '*' || rule =~ /^(\*\.)?([a-z\d][a-z\d-]*[a-z\d]\.)+[a-z]+$/
    end

    def matches(domain, pattern)
      if pattern == '*'
        true
      elsif pattern.start_with?('*.')
        domain.downcase.end_with?(pattern[1..-1].downcase)
      else
        domain.casecmp?(pattern)
      end
    end

    attr_accessor :next_id # The next ID to have been allocated to an entry
    attr_accessor :feature_set
  end
end
end
end
