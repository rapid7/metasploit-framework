# -*- coding: binary -*-

module Msf
module Ui
module Console
module CommandDispatcher

class DNS

  include Msf::Ui::Console::CommandDispatcher

  @@add_opts = Rex::Parser::Arguments.new(
    ['-r', '--rule'] => [true, 'Set a DNS wildcard entry to match against' ],
    ['-s', '--session'] => [true, 'Force the DNS request to occur over a particular channel (override routing rules)' ],
  )

  @@remove_opts = Rex::Parser::Arguments.new(
    ['-i'] => [true, 'Index to remove']
  )

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
      when '-s', '--session'
        session_ids = driver.framework.sessions.keys.map { |k| k.to_s }
        return session_ids.select { |id| id.start_with?(str) }
      when '-r', '--rule'
        # Hard to auto-complete a rule with any meaningful value; just return
        return
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

  def cmd_dns_help
    print_line "Manage Metasploit's DNS resolution behaviour"
    print_line
    print_line "Usage:"
    print_line "  dns [add] [--session <session_id>] [--rule <wildcard DNS entry>] <IP address> ..."
    print_line "  dns [remove/del] -i <entry id> [-i <entry id> ...]"
    print_line "  dns [flush-cache]"
    print_line "  dns [flush-entries]"
    print_line "  dns [print]"
    print_line "  dns [resolve] <hostname> ..."
    print_line
    print_line "Subcommands:"
    print_line "  add           - add a DNS resolution entry to resolve certain domain names through a particular DNS server"
    print_line "  remove        - delete a DNS resolution entry; 'del' is an alias"
    print_line "  print         - show all configured DNS resolution entries"
    print_line "  flush-entries - remove all configured DNS resolution entries"
    print_line "  flush-cache   - remove all cached DNS answers"
    print_line "  resolve       - resolve a hostname"
    print_line
    print_line "Examples:"
    print_line "  Display all current DNS nameserver entries"
    print_line "    dns"
    print_line "    dns print"
    print_line
    print_line "  Set the DNS server(s) to be used for *.metasploit.com to 192.168.1.10"
    print_line "    dns add --rule *.metasploit.com 192.168.1.10"
    print_line
    print_line "  Add multiple entries at once"
    print_line "    dns add --rule *.metasploit.com --rule *.google.com 192.168.1.10 192.168.1.11"
    print_line
    print_line "  Set the DNS server(s) to be used for *.metasploit.com to 192.168.1.10, but specifically to go through session 2"
    print_line "    dns add --session 2 --rule *.metasploit.com 192.168.1.10"
    print_line
    print_line "  Delete the DNS resolution rule with ID 3"
    print_line "    dns remove -i 3"
    print_line
    print_line "  Delete multiple entries in one command"
    print_line "    dns remove -i 3 -i 4 -i 5"
    print_line
    print_line "  Set the DNS server(s) to be used for all requests that match no rules"
    print_line "    dns add 8.8.8.8 8.8.4.4"
    print_line
    print_line "  Resolve a hostname using the current configuration"
    print_line "    dns resolve -f IPv6 www.metasploit.com"
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
      cmd_dns_help
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
        cmd_dns_help
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
    servers = []
    @@add_opts.parse(args) do |opt, idx, val|
      unless servers.empty? || opt.nil?
        raise ::ArgumentError.new("Invalid command near #{opt}")
      end
      case opt
      when '--rule', '-r'
        raise ::ArgumentError.new('No rule specified') if val.nil?

        rules.clear if first_rule # if the user defines even one rule, clear the defaults
        first_rule = false
        rules << val
      when '--session', '-s'
        if val.nil?
          raise ::ArgumentError.new('No session specified')
        end

        unless comm.nil?
          raise ::ArgumentError.new('Only one session can be specified')
        end

        comm = val
      when nil
        servers << val
      else
        raise ::ArgumentError.new("Unknown flag: #{opt}")
      end
    end

    # The remaining args should be the DNS servers

    if servers.length < 1
      raise ::ArgumentError.new("You must specify at least one DNS server")
    end

    servers.each do |host|
      unless Rex::Socket.is_ip_addr?(host)
        raise ::ArgumentError.new("Invalid DNS server: #{host}")
      end
    end

    comm_obj = nil

    unless comm.nil?
      raise ::ArgumentError.new("Not a valid number: #{comm}") unless comm =~ /^\d+$/
      comm_int = comm.to_i
      raise ::ArgumentError.new("Session does not exist: #{comm}") unless driver.framework.sessions.include?(comm_int)
      comm_obj = driver.framework.sessions[comm_int]
    end

    rules.each do |rule|
      print_warning("DNS rule #{rule} does not contain wildcards, so will not match subdomains") unless rule.include?('*')
      driver.framework.dns_resolver.add_nameserver(servers, comm: comm_obj, wildcard_rule: rule)
    end

    print_good("#{rules.length} DNS #{rules.length > 1 ? 'entries' : 'entry'} added")
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
      'Prefix'  => "\n",
      'Postfix' => "\n",
      'Columns'   => ['Hostname', 'IP Address']
    )
    names.each do |name|
      begin
        result = resolver.query(name, query_type)
      rescue NoResponseError
        tbl << [name, '[Failed To Resolve]']
      else
        if result.answer.empty?
          tbl << [name, '[Failed To Resolve]']
        else
          result.answer.select do |answer|
            answer.type == query_type
          end.map(&:address).map(&:to_s).each do |address|
            tbl << [name, address]
          end
        end
      end
    end
    print(tbl.to_s)
  end

  #
  # Remove all matching user-configured DNS entries
  #
  def remove_dns(*args)
    remove_ids = []
    @@remove_opts.parse(args) do |opt, idx, val|
      case opt
      when '-i'
        raise ::ArgumentError.new("Not a valid number: #{val}") unless val =~ /^\d+$/
        remove_ids << val.to_i
      end
    end

    removed = driver.framework.dns_resolver.remove_ids(remove_ids)
    difference = remove_ids.difference(removed.map { |entry| entry[:id] })
    print_warning("Some entries were not removed: #{difference.join(', ')}") unless difference.empty?
    if removed.length > 0
      print_good("#{removed.length} DNS #{removed.length > 1 ? 'entries' : 'entry'} removed")
      print_dns_set('Deleted entries', removed)
    end
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

  #
  # Get user-friendly text for displaying the session that this entry would go through
  #
  def prettify_comm(comm, dns_server)
    if comm.nil?
      channel = Rex::Socket::SwitchBoard.best_comm(dns_server)
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
    columns = ['ID', 'Rule', 'Resolver', 'Comm channel']

    tbl = Table.new(
      Table::Style::Default,
      'Header'    => heading,
      'Prefix'    => "\n",
      'Postfix'   => "\n",
      'Columns'   => columns,
      'SortIndex' => -1,
      'WordWrap'  => false,
    )
    result_set.each do |hash|
      if hash[:servers].length == 1
        tbl << [hash[:id], hash[:wildcard_rule], hash[:servers].first, prettify_comm(hash[:comm], hash[:servers].first)]
      elsif hash[:servers].length > 1
        # XXX: By default rex-text tables strip preceding whitespace:
        #   https://github.com/rapid7/rex-text/blob/1a7b639ca62fd9102665d6986f918ae42cae244e/lib/rex/text/table.rb#L221-L222
        #   So use https://en.wikipedia.org/wiki/Non-breaking_space as a workaround for now. A change should exist in Rex-Text to support this requirement
        indent = "\xc2\xa0\xc2\xa0\\_ "

        tbl << [hash[:id], hash[:wildcard_rule], '', '']
        hash[:servers].each do |server|
          tbl << ['.', indent, server, prettify_comm(hash[:comm], server)]
        end
      end
    end

    print(tbl.to_s) if tbl.rows.length > 0
  end

  def resolver
    self.driver.framework.dns_resolver
  end
end

end
end
end
end
