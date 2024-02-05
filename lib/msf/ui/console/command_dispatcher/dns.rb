# -*- coding: binary -*-

module Msf
module Ui
module Console
module CommandDispatcher

class DNS

  include Msf::Ui::Console::CommandDispatcher

  ADD_USAGE = 'dns [add] [--session <session id>] [--rule <wildcard DNS entry>] <resolver> ..."'.freeze
  @@add_opts = Rex::Parser::Arguments.new(
    ['-i', '--index'] => [true, 'Index to insert at'],
    ['-r', '--rule'] => [true, 'Set a DNS wildcard entry to match against' ],
    ['-s', '--session'] => [true, 'Force the DNS request to occur over a particular channel (override routing rules)' ]
  )

  REMOVE_USAGE = 'dns [remove/del] -i <entry id> [-i <entry id> ...]"'.freeze
  @@remove_opts = Rex::Parser::Arguments.new(
    ['-i', '--index'] => [true, 'Index to remove at']
  )

  RESOLVE_USAGE = 'dns [resolve] [-f <address family>] <hostname> ..."'.freeze
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

    if framework.features.enabled?(Msf::FeatureManager::DNS_FEATURE)
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

    if words.length == 1
      options = %w[ add delete flush-cache flush-entries print query remove resolve ]
      return options.select { |opt| opt.start_with?(str) }
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
            return # They're trying to specify a DNS server - we can't help them from here on out
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
    when 'flush-cache','flush-entries','help','print'
      # These commands don't have any arguments
      return
    when 'remove','delete'
      if words[-1] == '-i'
        ids = driver.framework.dns_resolver.upstream_entries.map { |entry| entry[:id].to_s }
        return ids.select { |id| id.start_with?(str) }
      else
        return @@remove_opts.option_keys.select { |opt| opt.start_with?(str) }
      end
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
      if respond_to?("#{args.first}_dns_help")
        # if it is a valid command with dedicated help information
        return send("#{args.first}_dns_help")
      elsif respond_to?("#{args.first}_dns")
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
    print_line "  #{REMOVE_USAGE}"
    print_line "  dns [flush-cache]"
    print_line "  dns [flush-entries]"
    print_line "  dns [print]"
    print_line "  #{RESOLVE_USAGE}"
    print_line "  dns [help] [subcommand]"
    print_line
    print_line "SUBCOMMANDS:"
    print_line "  add           - add a DNS resolution entry to resolve certain domain names through a particular DNS resolver"
    print_line "  remove        - delete a DNS resolution entry; 'del' is an alias"
    print_line "  print         - show all configured DNS resolution entries"
    print_line "  flush-entries - remove all configured DNS resolution entries"
    print_line "  flush-cache   - remove all cached DNS answers"
    print_line "  resolve       - resolve a hostname"
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
    return if driver.framework.dns_resolver.nil?

    args << 'print' if args.length == 0
    # Short-circuit help
    if args.delete("-h") || args.delete("--help")
      if respond_to?("#{args.first}_dns_help")
        # if it is a valid command with dedicated help information
        send("#{args.first}_dns_help")
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
      when "flush-entries"
        flush_entries_dns
      when "flush-cache"
        flush_cache_dns
      when "help"
        cmd_dns_help(*args)
      when "print"
        print_dns
      when "remove", "rm", "delete", "del"
        remove_dns(*args)
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
    position = -1
    @@add_opts.parse(args) do |opt, idx, val|
      unless resolvers.empty? || opt.nil?
        raise ::ArgumentError.new("Invalid command near #{opt}")
      end
      case opt
      when '-i', '--index'
        raise ::ArgumentError.new("Not a valid index: #{val}") unless val.to_i > 0

        position = val.to_i - 1
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
        resolvers << val
      else
        raise ::ArgumentError.new("Unknown flag: #{opt}")
      end
    end

    # The remaining args should be the DNS servers
    if resolvers.length < 1
      raise ::ArgumentError.new('You must specify at least one upstream DNS resolver')
    end

    resolvers.each do |host|
      unless Rex::Socket.is_ip_addr?(host) || SPECIAL_RESOLVERS.include?(host.downcase)
        raise ::ArgumentError.new("Invalid DNS resolver: #{host}")
      end
    end

    comm_obj = nil

    unless comm.nil?
      raise ::ArgumentError.new("Not a valid number: #{comm}") unless comm =~ /^\d+$/
      comm_int = comm.to_i
      raise ::ArgumentError.new("Session does not exist: #{comm}") unless driver.framework.sessions.include?(comm_int)
      comm_obj = driver.framework.sessions[comm_int]
      if resolvers.any? { |resolver| SPECIAL_RESOLVERS.include?(resolver.downcase) }
        print_warning("The session argument will be ignored for the system resolver")
      end
    end

    rules.each_with_index do |rule, rule_index|
      print_warning("DNS rule #{rule} does not contain wildcards, so will not match subdomains") unless rule.include?('*')
      driver.framework.dns_resolver.add_upstream_entry(
        resolvers,
        comm: comm_obj,
        wildcard: rule,
        position: (position == -1 ? -1 : position + rule_index)
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
    print_line "  system              - Use the host operating systems DNS resolution functionality (only for A/AAAA records)"
    print_line "  blackhole           - Drop all queries"
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
      'SortIndex' => -1,
      'WordWrap'  => false
    )
    names.each do |name|
      upstream_entry = resolver.upstream_entries.find { |ue| ue.matches_name?(name) }
      begin
        result = resolver.query(name, query_type)
      rescue NoResponseError
        tbl = append_resolver_cells!(tbl, upstream_entry, prefix: [name, '[Failed To Resolve]'])
      else
        if result.answer.empty?
          tbl = append_resolver_cells!(tbl, upstream_entry, prefix: [name, '[Failed To Resolve]'])
        else
          result.answer.select do |answer|
            answer.type == query_type
          end.map(&:address).map(&:to_s).each do |address|
            tbl = append_resolver_cells!(tbl, upstream_entry, prefix: [name, address])
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

    removed = resolver.remove_ids(remove_ids)
    print_warning('Some entries were not removed') unless removed.length == remove_ids.length
    if removed.length > 0
      print_good("#{removed.length} DNS #{removed.length > 1 ? 'entries' : 'entry'} removed")
      print_dns_set('Deleted entries', removed)
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
    print_line "  Delete multiple entries in one command"
    print_line "    dns remove -i 3 -i 4 -i 5"
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
    resolver.purge
    print_good('DNS entries flushed')
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

    upstream_entries = resolver.upstream_entries
    print_dns_set('Resolver rule entries', upstream_entries)

    if upstream_entries.empty?
      print_error('No DNS nameserver entries configured')
    end
  end

  private

  SPECIAL_RESOLVERS = [
    Rex::Proto::DNS::UpstreamResolver::TYPE_BLACKHOLE.to_s.downcase,
    Rex::Proto::DNS::UpstreamResolver::TYPE_SYSTEM.to_s.downcase
  ].freeze

  #
  # Get user-friendly text for displaying the session that this entry would go through
  #
  def prettify_comm(comm, upstream_resolver)
    if SPECIAL_RESOLVERS.include?(upstream_resolver.type.to_s)
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

  def print_dns_set(heading, result_set)
    return if result_set.length == 0
    columns = ['#', 'Rule', 'Resolver', 'Comm channel']

    tbl = Table.new(
      Table::Style::Default,
      'Header'    => heading,
      'Prefix'    => "\n",
      'Postfix'   => "\n",
      'Columns'   => columns,
      'SortIndex' => -1,
      'WordWrap'  => false,
    )
    result_set.each do |entry|
      tbl = append_resolver_cells!(tbl, entry)
    end

    print(tbl.to_s) if tbl.rows.length > 0
  end

  def append_resolver_cells!(tbl, entry, prefix: [], suffix: [])
    alignment_prefix = prefix.empty? ? [] : (['.'] * prefix.length)
    entry_index = resolver.upstream_entries.index(entry)
    entry_index += 1 if entry_index

    if entry.resolvers.length == 1
      tbl << prefix + [entry_index, entry.wildcard, entry.resolvers.first, prettify_comm(entry.comm, entry.resolvers.first)] + suffix
    elsif entry.resolvers.length > 1
      # XXX: By default rex-text tables strip preceding whitespace:
      #   https://github.com/rapid7/rex-text/blob/1a7b639ca62fd9102665d6986f918ae42cae244e/lib/rex/text/table.rb#L221-L222
      #   So use https://en.wikipedia.org/wiki/Non-breaking_space as a workaround for now. A change should exist in Rex-Text to support this requirement
      indent = "\xc2\xa0\xc2\xa0\\_ "

      tbl << prefix + [entry_index, entry.wildcard, '', ''] + suffix
      entry.resolvers.each do |resolver|
        tbl << alignment_prefix + ['.', indent, resolver, prettify_comm(entry.comm, resolver)] + ([''] * suffix.length)
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
