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
    # The custom nameserver entries that have been configured
    # @return [Array<Array>] An array containing two elements: The entries with rules, and the entries without rules
    def nameserver_entries
      [entries_with_rules, entries_without_rules]
    end

    def purge
      init
    end

    def nameservers_for_packet(packet)
      name = packet.question.qName
      dns_servers = []

      self.entries_with_rules.each do |entry|
        entry[:wildcard_rules].each do |rule|
          if matches(name, rule)
            dns_servers.concat([entry[:dns_server], entry[:comm]])
            break
          end
        end
      end

      # Only look at the rule-less entries if no rules were found (avoids DNS leaks)
      if dns_servers.empty?
        self.entries_without_rules.each do |entry|
          dns_servers.concat([entry[:dns_server], entry[:comm]])
        end
      end
      dns_servers.uniq!
    end

    def self.extended(mod)
      mod.init
    end

    private

    def matches(domain, pattern)
      true
    end

    attr_accessor :entries_with_rules # Set of custom nameserver entries that specify a rule
    attr_accessor :entries_without_rules # Set of custom nameserver entries that do not include a rule
    attr_accessor :next_id # The next ID to have been allocated to an entry
  end
end
end
end