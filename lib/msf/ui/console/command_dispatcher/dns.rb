# -*- coding: binary -*-

module Msf
module Ui
module Console
module CommandDispatcher

class DNS

  include Msf::Ui::Console::CommandDispatcher

  ADD_USAGE = 'dns [add] [--index <insertion index>] [--rule <wildcard DNS entry>] [--session <session id>] <resolver> ...'.freeze
  @@add_opts = Rex::Parser::Arguments.new(
    ['-i', '--index'] => [true, 'Index to insert at'],
    ['-r', '--rule'] => [true, 'Set a DNS wildcard entry to match against'],
    ['-s', '--session'] => [true, 'Force the DNS request to occur over a particular channel (override routing rules)']
  )

  ADD_STATIC_USAGE = 'dns [add-static] <hostname> <IP address> ...'.freeze

  REMOVE_USAGE = 'dns [remove/del] -i <entry id> [-i <entry id> ...]'.freeze
  @@remove_opts = Rex::Parser::Arguments.new(
    ['-i', '--index'] => [true, 'Index to remove at']
  )

  REMOVE_STATIC_USAGE = 'dns [remove-static] <hostname> [<IP address> ...]'.freeze

  RESET_CONFIG_USAGE = 'dns [reset-config] [-y/--yes] [--system]'.freeze
  @@reset_config_opts = Rex::Parser::Arguments.new(
    ['-y', '--yes'] => [false, 'Assume yes and do not prompt for confirmation before resetting'],
    ['--system'] => [false, 'Include the system resolver']
  )

  RESOLVE_USAGE = 'dns [resolve] [-f <address family>] <hostname> ...'.freeze
  @@resolve_opts = Rex::Parser::Arguments.new(
    # same usage syntax as Rex::Post::Meterpreter::Ui::Console::CommandDispatcher::Stdapi
    ['-f'] => [true,  'Address family - IPv4 or IPv6 (default IPv4)']
  )

  def initialize(driver)
    super
  end

  def name
    'DNS'
  end

  def commands
    commands = {}

    if framework.features.enabled?(Msf::FeatureManager::DNS)
      commands = {
        'dns' => "Manage Metasploit's DNS resolving behaviour"
      }
    end
    commands
  end

  #
  # Tab completion for the dns command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line. The array
  # contains at least one entry when tab completion has reached this stage since the command itself has been completed
  def cmd_dns_tabs(str, words)
    return if driver.framework.dns_resolver.nil?

    subcommands = %w[ add add-static delete flush-cache flush-entries flush-static help print query remove remove-static reset-config resolve ]
    if words.length == 1
      return subcommands.select { |opt| opt.start_with?(str) }
    end

    cmd = words[1]
    case cmd
    when 'add'
      # We expect a repeating pattern of tag (e.g. -r) and then a value (e.g. *.metasploit.com)
      # Once this pattern is violated, we're just specifying DNS servers at that point.
      tag_is_expected = true
      if words.length > 2
        words[2..-1].each do |word|
          if tag_is_expected && !word.start_with?('-')
            return
          end
          tag_is_expected = !tag_is_expected
        end
      end

      case words[-1]
      when '-r', '--rule'
        # Hard to auto-complete a rule with any meaningful value; just return
        return
      when '-s', '--session'
        session_ids = driver.framework.sessions.keys.map { |k| k.to_s }
        return session_ids.select { |id| id.start_with?(str) }
      when /^-/
        # Unknown tag
        return
      end

      options = @@add_opts.option_keys.select { |opt| opt.start_with?(str) }
      options << '' # Prevent tab-completion of a dash, given they could provide an IP address at this point
      return options
    when 'add-static'
      if words.length == 2
        # tab complete existing hostnames because they can have more than one IP address
        return resolver.static_hostnames.each.select { |hostname,_| hostname.downcase.start_with?(str.downcase) }.map { |hostname,_| hostname }
      end
    when 'help'
      # These commands don't have any arguments
      return subcommands.select { |sc| sc.start_with?(str) }
    when 'remove','delete'
      if words[-1] == '-i'
        return
      else
        return @@remove_opts.option_keys.select { |opt| opt.start_with?(str) }
      end
    when 'remove-static'
      if words.length == 2
        return resolver.static_hostnames.each.select { |hostname,_| hostname.downcase.start_with?(str.downcase) }.map { |hostname,_| hostname }
      elsif words.length > 2
        hostname = words[2]
        ip_addresses = resolver.static_hostnames.get(hostname, Dnsruby::Types::A) + resolver.static_hostnames.get(hostname, Dnsruby::Types::AAAA)
        return ip_addresses.map(&:to_s).select { |ip_address| ip_address.start_with?(str) }
      end
    when 'reset-config'
      @@reset_config_opts.option_keys.select { |opt| opt.start_with?(str) }
    when 'resolve','query'
      if words[-1] == '-f'
        families = %w[ IPv4 IPv6 ] # The family argument is case-insensitive
        return families.select { |family| family.downcase.start_with?(str.downcase) }
      else
        @@resolve_opts.option_keys.select { |opt| opt.start_with?(str) }
      end
    end
  end

  def cmd_dns_help(*args)
    if args.first.present?
      handler = "#{args.first.gsub('-', '_')}_dns"
      if respond_to?("#{handler}_help")
        # if it is a valid command with dedicated help information
        return send("#{handler}_help")
      elsif respond_to?(handler)
        # if it is a valid command without dedicated help information
        print_error("No help menu is available for #{args.first}")
        return
      else
        print_error("Invalid subcommand: #{args.first}")
      end
    end

    print_line "Manage Metasploit's DNS resolution behaviour"
    print_line
    print_line "USAGE:"
    print_line "  #{ADD_USAGE}"
    print_line "  #{ADD_STATIC_USAGE}"
    print_line "  #{REMOVE_USAGE}"
    print_line "  #{REMOVE_STATIC_USAGE}"
    print_line "  dns [flush-cache]"
    print_line "  dns [flush-entries]"
    print_line "  dns [flush-static]"
    print_line "  dns [print]"
    print_line "  #{RESET_CONFIG_USAGE}"
    print_line "  #{RESOLVE_USAGE}"
    print_line "  dns [help] [subcommand]"
    print_line
    print_line "SUBCOMMANDS:"
    print_line "  add           - Add a DNS resolution entry to resolve certain domain names through a particular DNS resolver"
    print_line "  add-static    - Add a statically defined hostname"
    print_line "  flush-cache   - Remove all cached DNS answers"
    print_line "  flush-entries - Remove all configured DNS resolution entries"
    print_line "  flush-static  - Remove all statically defined hostnames"
    print_line "  print         - Show all configured DNS resolution entries"
    print_line "  remove        - Delete a DNS resolution entry"
    print_line "  remove-static - Delete a statically defined hostname"
    print_line "  reset-config  - Reset the DNS configuration"
    print_line "  resolve       - Resolve a hostname"
    print_line
    print_line "EXAMPLES:"
    print_line "  Display help information for the 'add' subcommand"
    print_line "    dns help add"
    print_line
  end

  #
  # Manage Metasploit's DNS resolution rules
  #
  def cmd_dns(*args)
    if driver.framework.dns_resolver.nil?
      print_warning("Run the #{Msf::Ui::Tip.highlight("save")} command and restart the console for this feature configuration to take effect.")
      return
    end

    args << 'print' if args.length == 0
    # Short-circuit help
    if args.delete("-h") || args.delete("--help")
      subcommand = args.first
      if subcommand && respond_to?("#{subcommand.gsub('-', '_')}_dns_help")
        # if it is a valid command with dedicated help information
        send("#{subcommand.gsub('-', '_')}_dns_help")
      else
        # otherwise print the top-level help information
        cmd_dns_help
      end
      return
    end

    action = args.shift
    begin
      case action
      when "add"
        add_dns(*args)
      when "add-static"
        add_static_dns(*args)
      when "flush-entries"
        flush_entries_dns
      when "flush-cache"
        flush_cache_dns
      when "flush-static"
        flush_static_dns
      when "help"
        cmd_dns_help(*args)
      when "print"
        print_dns
      when "remove", "rm", "delete", "del"
        remove_dns(*args)
      when "remove-static"
        remove_static_dns(*args)
      when "reset-config"
        reset_config_dns(*args)
      when "resolve", "query"
        resolve_dns(*args)
      else
        print_error("Invalid command. To view help: dns -h")
      end
    rescue ::ArgumentError => e
      print_error(e.message)
    end
  end

  def add_dns(*args)
    rules = ['*']
    first_rule = true
    comm = nil
    resolvers = []
    index = -1
    @@add_opts.parse(args) do |opt, idx, val|
      unless resolvers.empty? || opt.nil?
        raise ::ArgumentError.new("Invalid command near #{opt}")
      end
      case opt
      when '-i', '--index'
        raise ::ArgumentError.new("Not a valid index: #{val}") unless val.to_i > 0

        index = val.to_i - 1
      when '-r', '--rule'
        raise ::ArgumentError.new('No rule specified') if val.nil?

        rules.clear if first_rule # if the user defines even one rule, clear the defaults
        first_rule = false
        rules << val
      when '-s', '--session'
        if val.nil?
          raise ::ArgumentError.new('No session specified')
        end

        unless comm.nil?
          raise ::ArgumentError.new('Only one session can be specified')
        end

        comm = val
      when nil
        val = 'black-hole' if val.casecmp?('blackhole')
        resolvers << val
      else
        raise ::ArgumentError.new("Unknown flag: #{opt}")
      end
    end

    # The remaining args should be the DNS servers
    if resolvers.length < 1
      raise ::ArgumentError.new('You must specify at least one upstream DNS resolver')
    end

    resolvers.each do |resolver|
      unless Rex::Proto::DNS::UpstreamRule.valid_resolver?(resolver)
        message = "Invalid DNS resolver: #{resolver}."
        if (suggestions = Rex::Proto::DNS::UpstreamRule.spell_check_resolver(resolver)).present?
          message << " Did you mean #{suggestions.first}?"
        end

        raise ::ArgumentError.new(message)
      end
    end

    comm_obj = nil

    unless comm.nil?
      raise ::ArgumentError.new("Not a valid session: #{comm}") unless comm =~ /\A-?[0-9]+\Z/

      comm_obj = driver.framework.sessions.get(comm.to_i)
      raise ::ArgumentError.new("Session does not exist: #{comm}") unless comm_obj
      raise ::ArgumentError.new("Socket Comm (Session #{comm}) does not implement Rex::Socket::Comm") unless comm_obj.is_a? ::Rex::Socket::Comm

      if resolvers.any? { |resolver| SPECIAL_RESOLVERS.include?(resolver.downcase) }
        print_warning("The session argument will be ignored for the system resolver")
      end
    end

    rules.each_with_index do |rule, offset|
      print_warning("DNS rule #{rule} does not contain wildcards, it will not match subdomains") unless rule.include?('*')
      driver.framework.dns_resolver.add_upstream_rule(
        resolvers,
        comm: comm_obj,
        wildcard: rule,
        index: (index == -1 ? -1 : offset + index)
      )
    end

    print_good("#{rules.length} DNS #{rules.length > 1 ? 'entries' : 'entry'} added")
  end

  def add_dns_help
    print_line "USAGE:"
    print_line "  #{ADD_USAGE}"
    print_line @@add_opts.usage
    print_line "RESOLVERS:"
    print_line "  ipv4 / ipv6 address - The IP address of an upstream DNS server to resolve from"
    print_line "  #{Rex::Proto::DNS::UpstreamResolver::Type::BLACK_HOLE.to_s.ljust(19)} - Drop all queries"
    print_line "  #{Rex::Proto::DNS::UpstreamResolver::Type::STATIC.to_s.ljust(19)    } - Reply with statically configured addresses (only for A/AAAA records)"
    print_line "  #{Rex::Proto::DNS::UpstreamResolver::Type::SYSTEM.to_s.ljust(19)    } - Use the host operating systems DNS resolution functionality (only for A/AAAA records)"
    print_line
    print_line "EXAMPLES:"
    print_line "  Set the DNS server(s) to be used for *.metasploit.com to 192.168.1.10"
    print_line "    dns add --rule *.metasploit.com 192.168.1.10"
    print_line
    print_line "  Add multiple entries at once"
    print_line "    dns add --rule *.metasploit.com --rule *.google.com 192.168.1.10 192.168.1.11"
    print_line
    print_line "  Set the DNS server(s) to be used for *.metasploit.com to 192.168.1.10, but specifically to go through session 2"
    print_line "    dns add --session 2 --rule *.metasploit.com 192.168.1.10"
  end

  def add_static_dns(*args)
    if args.length < 2
      raise ::ArgumentError.new('A hostname and IP address must be provided')
    end

    hostname = args.shift
    if !Rex::Proto::DNS::StaticHostnames.is_valid_hostname?(hostname)
      raise ::ArgumentError.new("Invalid hostname: #{hostname}")
    end

    ip_addresses = args
    if (ip_address = ip_addresses.find { |a| !Rex::Socket.is_ip_addr?(a) })
      raise ::ArgumentError.new("Invalid IP address: #{ip_address}")
    end

    ip_addresses.each do |ip_address|
      resolver.static_hostnames.add(hostname, ip_address)
      print_status("Added static hostname mapping #{hostname} to #{ip_address}")
    end
  end

  def add_static_dns_help
    print_line "USAGE:"
    print_line "  #{ADD_STATIC_USAGE}"
    print_line
    print_line "EXAMPLES:"
    print_line "  Define a static entry mapping localhost6 to ::1"
    print_line "    dns add-static localhost6 ::1"
  end

  #
  # Query a hostname using the configuration. This is useful for debugging and
  # inspecting the active settings.
  #
  def resolve_dns(*args)
    names = []
    query_type = Dnsruby::Types::A

    @@resolve_opts.parse(args) do |opt, idx, val|
      unless names.empty? || opt.nil?
        raise ::ArgumentError.new("Invalid command near #{opt}")
      end
      case opt
      when '-f'
        case val.downcase
        when 'ipv4'
          query_type = Dnsruby::Types::A
        when'ipv6'
          query_type = Dnsruby::Types::AAAA
        else
          raise ::ArgumentError.new("Invalid family: #{val}")
        end
      when nil
        names << val
      else
        raise ::ArgumentError.new("Unknown flag: #{opt}")
      end
    end

    if names.length < 1
      raise ::ArgumentError.new('You must specify at least one hostname to resolve')
    end

    tbl = Table.new(
      Table::Style::Default,
      'Header'    => 'Host resolutions',
      'Prefix'    => "\n",
      'Postfix'   => "\n",
      'Columns'   => ['Hostname', 'IP Address', 'Rule #', 'Rule', 'Resolver', 'Comm channel'],
      'ColProps'  => { 'Hostname' => { 'Strip' => false } },
      'SortIndex' => -1,
      'WordWrap'  => false
    )
    names.each do |name|
      upstream_rule = resolver.upstream_rules.find { |ur| ur.matches_name?(name) }
      if upstream_rule.nil?
        tbl << [name, '[Failed To Resolve]', '', '', '', '']
        next
      end

      upstream_rule_idx = resolver.upstream_rules.index(upstream_rule) + 1

      begin
        result = resolver.query(name, query_type)
      rescue NoResponseError
        tbl = append_resolver_cells!(tbl, upstream_rule, prefix: [name, '[Failed To Resolve]'], index: upstream_rule_idx)
      else
        if result.answer.empty?
          tbl = append_resolver_cells!(tbl, upstream_rule, prefix: [name, '[Failed To Resolve]'], index: upstream_rule_idx)
        else
          result.answer.select do |answer|
            answer.type == query_type
          end.map(&:address).map(&:to_s).each do |address|
            tbl = append_resolver_cells!(tbl, upstream_rule, prefix: [name, address], index: upstream_rule_idx)
          end
        end
      end
    end
    print(tbl.to_s)
  end

  def resolve_dns_help
    print_line "USAGE:"
    print_line "  #{RESOLVE_USAGE}"
    print_line @@resolve_opts.usage
    print_line "EXAMPLES:"
    print_line "  Resolve a hostname to an IPv6 address using the current configuration"
    print_line "    dns resolve -f IPv6 www.metasploit.com"
    print_line
  end

  #
  # Remove all matching user-configured DNS entries
  #
  def remove_dns(*args)
    remove_ids = []
    @@remove_opts.parse(args) do |opt, idx, val|
      case opt
      when '-i', '--index'
        raise ::ArgumentError.new("Not a valid index: #{val}") unless val.to_i > 0

        remove_ids << val.to_i - 1
      end
    end

    if remove_ids.empty?
      raise ::ArgumentError.new('At least one index to remove must be provided')
    end

    removed = resolver.remove_ids(remove_ids)
    print_warning('Some entries were not removed') unless removed.length == remove_ids.length
    if removed.length > 0
      print_good("#{removed.length} DNS #{removed.length > 1 ? 'entries' : 'entry'} removed")
      print_dns_set('Deleted entries', removed, ids: [nil] * removed.length)
    end
  end

  def remove_dns_help
    print_line "USAGE:"
    print_line "  #{REMOVE_USAGE}"
    print_line(@@remove_opts.usage)
    print_line "EXAMPLES:"
    print_line "  Delete the DNS resolution rule #3"
    print_line "    dns remove -i 3"
    print_line
    print_line "  Delete multiple rules in one command"
    print_line "    dns remove -i 3 -i 4 -i 5"
    print_line
  end

  def remove_static_dns(*args)
    if args.length < 1
      raise ::ArgumentError.new('A hostname must be provided')
    end

    hostname = args.shift
    if !Rex::Proto::DNS::StaticHostnames.is_valid_hostname?(hostname)
      raise ::ArgumentError.new("Invalid hostname: #{hostname}")
    end

    ip_addresses = args
    if ip_addresses.empty?
      ip_addresses = resolver.static_hostnames.get(hostname, Dnsruby::Types::A) + resolver.static_hostnames.get(hostname, Dnsruby::Types::AAAA)
      if ip_addresses.empty?
        print_status("There are no definitions for hostname: #{hostname}")
      end
    elsif (ip_address = ip_addresses.find { |ip| !Rex::Socket.is_ip_addr?(ip) })
      raise ::ArgumentError.new("Invalid IP address: #{ip_address}")
    end

    ip_addresses.each do |ip_address|
      resolver.static_hostnames.delete(hostname, ip_address)
      print_status("Removed static hostname mapping #{hostname} to #{ip_address}")
    end
  end

  def remove_static_dns_help
    print_line "USAGE:"
    print_line "  #{REMOVE_STATIC_USAGE}"
    print_line
    print_line "EXAMPLES:"
    print_line "  Remove all IPv4 and IPv6 addresses for 'localhost'"
    print_line "    dns remove-static localhost"
    print_line
  end

  def reset_config_dns(*args)
    add_system_resolver = false
    should_confirm = true
    @@reset_config_opts.parse(args) do |opt, idx, val|
      case opt
      when '--system'
        add_system_resolver = true
      when '-y', '--yes'
        should_confirm = false
      end
    end

    if should_confirm
      print("Are you sure you want to reset the DNS configuration? [y/N]: ")
      response = gets.downcase.chomp
      return unless response =~ /^y/i
    end

    resolver.reinit
    print_status('The DNS configuration has been reset')

    if add_system_resolver
      # if the user requested that we add the system resolver
      system_resolver = Rex::Proto::DNS::UpstreamResolver.create_system
      # first find the default, catch-all rule
      default_rule = resolver.upstream_rules.find { |ur| ur.matches_all? }
      if default_rule.nil?
        resolver.add_upstream_rule([ system_resolver ])
      else
        # if the first resolver is for static hostnames, insert after that one
        if default_rule.resolvers.first&.type == Rex::Proto::DNS::UpstreamResolver::Type::STATIC
          index = 1
        else
          index = 0
        end
        default_rule.resolvers.insert(index, system_resolver)
      end
    end

    print_dns

    if ENV['PROXYCHAINS_CONF_FILE'] && !add_system_resolver
      print_warning('Detected proxychains but the system resolver was not added')
    end
  end

  def reset_config_dns_help
    print_line "USAGE:"
    print_line "  #{RESET_CONFIG_USAGE}"
    print_line @@reset_config_opts.usage
    print_line "EXAMPLES:"
    print_line "  Reset the configuration without prompting to confirm"
    print_line "    dns reset-config --yes"
    print_line
  end

  #
  # Delete all cached DNS answers
  #
  def flush_cache_dns
    resolver.cache.flush
    print_good('DNS cache flushed')
  end

  #
  # Delete all user-configured DNS settings
  #
  def flush_entries_dns
    resolver.flush
    print_good('DNS entries flushed')
  end

  def flush_static_dns
    resolver.static_hostnames.flush
    print_good('DNS static hostnames flushed')
  end

  #
  # Display the user-configured DNS settings
  #
  def print_dns
    default_domain = 'N/A'
    if resolver.defname? && resolver.domain.present?
      default_domain = resolver.domain
    end
    print_line("Default search domain: #{default_domain}")

    searchlist = resolver.searchlist
    case searchlist.length
    when 0
      print_line('Default search list:   N/A')
    when 1
      print_line("Default search list:   #{searchlist.first}")
    else
      print_line('Default search list:')
      searchlist.each do |entry|
        print_line("  * #{entry}")
      end
    end
    print_line("Current cache size:    #{resolver.cache.records.length}")

    upstream_rules = resolver.upstream_rules
    print_dns_set('Resolver rule entries', upstream_rules, ids: (1..upstream_rules.length).to_a)
    if upstream_rules.empty?
      print_line
      print_error('No DNS nameserver entries configured')
    end

    tbl = Table.new(
      Table::Style::Default,
      'Header'    => 'Static hostnames',
      'Prefix'    => "\n",
      'Postfix'   => "\n",
      'Columns'   => ['Hostname', 'IPv4 Address', 'IPv6 Address'],
      'ColProps'  => { 'Hostname' => { 'Strip' => false } },
      'SortIndex' => -1,
      'WordWrap'  => false
    )
    resolver.static_hostnames.sort_by { |hostname, _| hostname }.each do |hostname, addresses|
      ipv4_addresses = addresses.fetch(Dnsruby::Types::A, []).sort_by(&:to_i)
      ipv6_addresses = addresses.fetch(Dnsruby::Types::AAAA, []).sort_by(&:to_i)
      if (ipv4_addresses.length <= 1 && ipv6_addresses.length <= 1) && ((ipv4_addresses + ipv6_addresses).length > 0)
        tbl << [hostname, ipv4_addresses.first, ipv6_addresses.first]
      else
        tbl << [hostname, '', '']
        0.upto([ipv4_addresses.length, ipv6_addresses.length].max - 1) do |idx|
          tbl << [TABLE_INDENT, ipv4_addresses[idx], ipv6_addresses[idx]]
        end
      end
    end
    print_line(tbl.to_s)
    if resolver.static_hostnames.empty?
      print_line('No static hostname entries are configured')
    end
  end

  private

  SPECIAL_RESOLVERS = [
    Rex::Proto::DNS::UpstreamResolver::Type::BLACK_HOLE.to_s.downcase,
    Rex::Proto::DNS::UpstreamResolver::Type::SYSTEM.to_s.downcase
  ].freeze

  TABLE_INDENT = "  \\_ ".freeze

  #
  # Get user-friendly text for displaying the session that this entry would go through
  #
  def prettify_comm(comm, upstream_resolver)
    if !Rex::Socket.is_ip_addr?(upstream_resolver.destination)
      'N/A'
    elsif comm.nil?
      channel = Rex::Socket::SwitchBoard.best_comm(upstream_resolver.destination)
      if channel.nil?
        nil
      else
        "Session #{channel.sid} (route)"
      end
    else
      if comm.alive?
        "Session #{comm.sid}"
      else
        "Closed session (#{comm.sid})"
      end
    end
  end

  def print_dns_set(heading, result_set, ids: [])
    return if result_set.length == 0
    columns = ['#', 'Rule', 'Resolver', 'Comm channel']
    col_props = { 'Rule' => { 'Strip' => false } }

    tbl = Table.new(
      Table::Style::Default,
      'Header'    => heading,
      'Prefix'    => "\n",
      'Postfix'   => "\n",
      'Columns'   => columns,
      'ColProps' => col_props,
      'SortIndex' => -1,
      'WordWrap'  => false
    )
    result_set.each_with_index do |entry, index|
      tbl = append_resolver_cells!(tbl, entry, index: ids[index])
    end

    print(tbl.to_s) if tbl.rows.length > 0
  end

  def append_resolver_cells!(tbl, entry, prefix: [], suffix: [], index: nil)
    alignment_prefix = prefix.empty? ? [] : (['.'] * prefix.length)

    if entry.resolvers.length == 1
      tbl << prefix + [index.to_s, entry.wildcard, entry.resolvers.first, prettify_comm(entry.comm, entry.resolvers.first)] + suffix
    elsif entry.resolvers.length > 1
      tbl << prefix + [index.to_s, entry.wildcard, '', ''] + suffix
      entry.resolvers.each do |resolver|
        tbl << alignment_prefix + ['.', TABLE_INDENT, resolver, prettify_comm(entry.comm, resolver)] + ([''] * suffix.length)
      end
    end
    tbl
  end

  def resolver
    self.driver.framework.dns_resolver
  end
end

end
end
end
end
