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
      self.entries_with_rules = []
      self.entries_without_rules = []
      self.next_id = 0
    end

    #
    # Save the custom settings to the MSF config file
    #
    def save_config
      new_config = {}
      [self.entries_with_rules, self.entries_without_rules].each do |entry_set|
        entry_set.each do |entry|
          key = entry[:id].to_s
          val = [entry[:wildcard_rules].join(','),
                 entry[:dns_server],
                 (!entry[:comm].nil?).to_s
                ].join(';')
          new_config[key] = val
        end
      end

      Msf::Config.save(CONFIG_KEY => new_config)
    end

    #
    # Load the custom settings from the MSF config file
    #
    def load_config
      config = Msf::Config.load

      with_rules = []
      without_rules = []
      next_id = 0

      dns_settings = config.fetch(CONFIG_KEY, {}).each do |name, value|
        id = name.to_i
        wildcard_rules, dns_server, uses_comm = value.split(';')
        wildcard_rules = wildcard_rules.split(',')

        raise Msf::Config::ConfigError.new('DNS parsing failed: Comm must be true or false') unless ['true','false'].include?(uses_comm)
        raise Msf::Config::ConfigError.new('Invalid DNS config: Invalid DNS server') unless Rex::Socket.is_ip_addr?(dns_server)
        raise Msf::Config::ConfigError.new('Invalid DNS config: Invalid rule') unless wildcard_rules.all? {|rule| valid_rule?(rule)}

        comm = uses_comm == 'true' ? CommSink.new : nil
        entry = {
          :wildcard_rules => wildcard_rules,
          :dns_server => dns_server,
          :comm => comm,
          :id => id
        }

        if wildcard_rules.empty?
          without_rules << entry
        else
          with_rules << entry
        end

        next_id = [id + 1, next_id].max
      end

      # Now that config has successfully read, update the global values
      self.entries_with_rules = with_rules
      self.entries_without_rules = without_rules
      self.next_id = next_id
    end

    # Add a custom nameserver entry to the custom provider
    # @param wildcard_rules [Array<String>] The wildcard rules to match a DNS request against
    # @param dns_server [Array<String>] The list of IP addresses that would be used for this custom rule
    # @param comm [Msf::Session::Comm] The communication channel to be used for these DNS requests
    def add_nameserver(wildcard_rules, dns_server, comm)
      raise ::ArgumentError.new("Invalid DNS server: #{dns_server}") unless Rex::Socket.is_ip_addr?(dns_server)
      wildcard_rules.each do |rule|
        raise ::ArgumentError.new("Invalid rule: #{rule}") unless valid_rule?(rule)
      end

      entry = {
        :wildcard_rules => wildcard_rules,
        :dns_server => dns_server,
        :comm => comm,
        :id => self.next_id
      }
      self.next_id += 1
      if wildcard_rules.empty?
        entries_without_rules << entry
      else
        entries_with_rules << entry
      end
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
        removed_with, remaining_with = self.entries_with_rules.partition {|entry| entry[:id] == id}
        self.entries_with_rules.replace(remaining_with)

        removed_without, remaining_without = self.entries_without_rules.partition {|entry| entry[:id] == id}
        self.entries_without_rules.replace(remaining_without)

        removed.concat(removed_with)
        removed.concat(removed_without)
      end

      removed
    end

    #
    # The custom nameserver entries that have been configured
    # @return [Array<Array>] An array containing two elements: The entries with rules, and the entries without rules
    #
    def nameserver_entries
      [entries_with_rules, entries_without_rules]
    end

    def purge
      init
    end

    # The nameservers that match the given packet
    # @param packet [Dnsruby::Message] The DNS packet to be sent
    # @raise [ResolveError] If the packet contains multiple questions, which would end up sending to a different set of nameservers
    # @return [Array<Array>] A list of nameservers, each with Rex::Socket options
    #
    def nameservers_for_packet(packet)
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
        dns_servers = []

        self.entries_with_rules.each do |entry|
          entry[:wildcard_rules].each do |rule|
            if matches(name, rule)
              socket_options = {}
              socket_options['Comm'] = entry[:comm] unless entry[:comm].nil?
              dns_servers.append([entry[:dns_server], socket_options])
              break
            end
          end
        end

        # Only look at the rule-less entries if no rules were found (avoids DNS leaks)
        if dns_servers.empty?
          self.entries_without_rules.each do |entry|
            socket_options = {}
            socket_options['Comm'] = entry[:comm] unless entry[:comm].nil?
            dns_servers.append([entry[:dns_server], socket_options])
          end
        end

        if dns_servers.empty?
          # Fall back to default nameservers
          dns_servers = super
        end
        results_from_all_questions << dns_servers.uniq
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

    private
    #
    # Is the given wildcard DNS entry valid?
    #
    def valid_rule?(rule)
      rule =~ /^(\*\.)?([a-z\d][a-z\d-]*[a-z\d]\.)+[a-z]+$/
    end


    def matches(domain, pattern)
      if pattern.start_with?('*.')
        domain.downcase.end_with?(pattern[1..-1].downcase)
      else
        domain.casecmp?(pattern)
      end
    end

    attr_accessor :entries_with_rules # Set of custom nameserver entries that specify a rule
    attr_accessor :entries_without_rules # Set of custom nameserver entries that do not include a rule
    attr_accessor :next_id # The next ID to have been allocated to an entry
    attr_accessor :feature_set
  end
end
end
end