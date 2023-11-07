module Rex
module Proto
module DNS

  ##
  # Provides a DNS resolver the ability to use different nameservers
  # for different requests, based on the domain being queried.
  ##
  module CustomNameserverProvider

    def init
      self.entries_with_rules = []
      self.entries_without_rules = []
      self.next_id = 0
    end

    # Add a custom nameserver entry to the custom provider
    # @param [wildcard_rules] Array<String> The wildcard rules to match a DNS request against
    # @param [dns_server] Array<String> The list of IP addresses that would be used for this custom rule
    # @param comm [Integer] The communication channel to be used for these DNS requests
    def add_nameserver(wildcard_rules, dns_server, comm)
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
    def remove_ids(ids)
      ids.each do |id|
        self.entries_with_rules.delete_if {|entry| entry[:id] == id}
        self.entries_without_rules.delete_if {|entry| entry[:id] == id}
      end
    end

    #
    # The custom nameserver entries that have been configured
    # @return [Array<Array>] An array containing two elements: The entries with rules, and the entries without rules
    def nameserver_entries
      [entries_with_rules, entries_without_rules]
    end

    def purge
      init
    end

    def nameservers_for_packet(packet)
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
            socket_options = {}
            socket_options['Comm'] = entry[:comm] unless entry[:comm].nil?
            if matches(name, rule)
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

    private

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
  end
end
end
end