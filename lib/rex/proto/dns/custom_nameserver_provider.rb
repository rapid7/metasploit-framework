require 'rex/proto/dns/upstream_resolver'

module Rex
module Proto
module DNS

  ##
  # Provides a DNS resolver the ability to use different nameservers
  # for different requests, based on the domain being queried.
  ##
  module CustomNameserverProvider
    CONFIG_KEY_BASE = 'framework/dns'
    CONFIG_VERSION = Rex::Version.new('1.0')

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
      @upstream_rules = []

      resolvers = [UpstreamResolver.create_static]
      if @config[:nameservers].empty?
        # if no nameservers are specified, fallback to the system
        resolvers << UpstreamResolver.create_system
      else
        # migrate the originally configured name servers
        resolvers += @config[:nameservers].map(&:to_s)
        @config[:nameservers].clear
      end

      add_upstream_rule(resolvers)

      nil
    end

    # Reinitialize the configuration to its original state.
    def reinit
      parse_config_file
      parse_environment_variables

      self.static_hostnames.flush
      self.static_hostnames.parse_hosts_file

      init

      cache.flush if respond_to?(:cache)

      nil
    end

    # Check whether or not there is configuration data in Metasploit's configuration file which is persisted on disk.
    def has_config?
      config = Msf::Config.load
      version = config.fetch(CONFIG_KEY_BASE, {}).fetch('configuration_version', nil)
      if version.nil?
        @logger.info 'DNS configuration can not be loaded because the version is missing'
        return false
      end

      their_version = Rex::Version.new(version)
      if their_version > CONFIG_VERSION # if the config is newer, it's incompatible (we only guarantee backwards compat)
        @logger.info "DNS configuration version #{their_version} can not be loaded because it is too new"
        return false
      end

      my_minimum_version = Rex::Version.new(CONFIG_VERSION.canonical_segments.first.to_s)
      if their_version < my_minimum_version # can not be older than our major version
        @logger.info "DNS configuration version #{their_version} can not be loaded because it is too old"
        return false
      end

      true
    end

    #
    # Save the custom settings to the MSF config file
    #
    def save_config
      new_config = {
        'configuration_version' => CONFIG_VERSION.to_s
      }
      Msf::Config.save(CONFIG_KEY_BASE => new_config)

      save_config_upstream_rules
      save_config_static_hostnames
    end

    #
    # Load the custom settings from the MSF config file
    #
    def load_config
      unless has_config?
        raise ResolverError.new('There is no compatible configuration data to load')
      end

      load_config_entries
      load_config_static_hostnames
    end

    # Add a custom nameserver entry to the custom provider.
    #
    # @param [Array<String>] resolvers The list of upstream resolvers that would be used for this custom rule.
    # @param [Msf::Session::Comm] comm The communication channel to be used for these DNS requests.
    # @param [String] wildcard The wildcard rule to match a DNS request against.
    # @param [Integer] index The index at which to insert the rule, defaults to -1 to append it at the end.
    def add_upstream_rule(resolvers, comm: nil, wildcard: '*', index: -1)
      resolvers = [resolvers] if resolvers.is_a?(String) # coerce into an array of strings

      @upstream_rules.insert(index, UpstreamRule.new(
        wildcard: wildcard,
        resolvers: resolvers,
        comm: comm
      ))
    end

    #
    # Remove upstream rules with the given indexes
    # Ignore entries that are not found
    # @param ids [Array<Integer>] The IDs to removed
    # @return [Array<UpstreamRule>] The removed entries
    def remove_ids(ids)
      removed = []
      ids.sort.reverse.each do |id|
        upstream_rule = @upstream_rules.delete_at(id)
        removed << upstream_rule if upstream_rule
      end

      removed.reverse
    end

    def flush
      @upstream_rules.clear
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
        upstream_rule = self.upstream_rules.find { |ur| ur.matches_name?(name) }

        if upstream_rule
          upstream_resolvers = upstream_rule.resolvers
        else
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

    def upstream_rules
      @upstream_rules.dup
    end

    private

    def load_config_entries
      config = Msf::Config.load

      with_rules = []
      config.fetch("#{CONFIG_KEY_BASE}/rules", {}).each do |_name, value|
        wildcard, resolvers, uses_comm = value.split(';')
        wildcard = '*' if wildcard.blank?
        resolvers = resolvers.split(',')
        uses_comm.downcase!

        raise Rex::Proto::DNS::Exceptions::ConfigError.new('DNS parsing failed: Comm must be true or false') unless ['true','false'].include?(uses_comm)
        raise Rex::Proto::DNS::Exceptions::ConfigError.new('Invalid DNS config: Invalid upstream DNS resolver') unless resolvers.all? {|resolver| UpstreamRule.valid_resolver?(resolver) }
        raise Rex::Proto::DNS::Exceptions::ConfigError.new('Invalid DNS config: Invalid rule') unless UpstreamRule.valid_wildcard?(wildcard)

        comm = uses_comm == 'true' ? CommSink.new : nil
        with_rules <<  UpstreamRule.new(
          wildcard: wildcard,
          resolvers: resolvers,
          comm: comm
        )
      end

      # Now that config has successfully read, update the global values
      @upstream_rules = with_rules
    end

    def load_config_static_hostnames
      config = Msf::Config.load

      static_hostnames.flush
      config.fetch("#{CONFIG_KEY_BASE}/static_hostnames", {}).each do |_name, value|
        hostname, ip_addresses = value.split(';', 2)
        ip_addresses.split(',').each do |ip_address|
          next if ip_address.blank?

          unless Rex::Socket.is_ip_addr?(ip_address)
            raise Rex::Proto::DNS::Exceptions::ConfigError.new('Invalid DNS config: Invalid IP address')
          end

          static_hostnames.add(hostname, ip_address)
        end
      end
    end

    def save_config_upstream_rules
      new_config = {}
      @upstream_rules.each_with_index do |entry, index|
        val = [
          entry.wildcard,
          entry.resolvers.map do |resolver|
            resolver.type == Rex::Proto::DNS::UpstreamResolver::Type::DNS_SERVER ? resolver.destination : resolver.type.to_s
          end.join(','),
          (!entry.comm.nil?).to_s
        ].join(';')
        new_config["##{index}"] = val
      end
      Msf::Config.save("#{CONFIG_KEY_BASE}/rules" => new_config)
    end

    def save_config_static_hostnames
      new_config = {}
      static_hostnames.each_with_index do |(hostname, addresses), index|
        val = [
          hostname,
          (addresses.fetch(Dnsruby::Types::A, []) + addresses.fetch(Dnsruby::Types::AAAA, [])).join(',')
        ].join(';')
        new_config["##{index}"] = val
      end
      Msf::Config.save("#{CONFIG_KEY_BASE}/static_hostnames" => new_config)
    end

    attr_accessor :feature_set
  end
end
end
end
