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
        'dns'        => "Manage Metasploit's DNS resolving behaviour"
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
      options = ['add','del','remove','purge','print']
      return options.select { |opt| opt.start_with?(str) }
    end

    cmd = words[1]
    case cmd
    when 'purge','print'
      # These commands don't have any arguments
      return
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
    when 'del','remove'
      if words[-1] == '-i'
        ids = driver.framework.dns_resolver.nameserver_entries.flatten.map { |entry| entry[:id].to_s }
        return ids.select { |id| id.start_with? str }
      else
        return @@remove_opts.option_keys.select { |opt| opt.start_with?(str) }
      end
    end
  end

  def cmd_dns_help
    print_line "Manage Metasploit's DNS resolution behaviour"
    print_line
    print_line "Usage:"
    print_line "  dns [add] [--session <session_id>] [--rule <wildcard DNS entry>] <IP Address> <IP Address> ..."
    print_line "  dns [remove/del] -i <entry id> [-i <entry id> ...]"
    print_line "  dns [purge]"
    print_line "  dns [print]"
    print_line
    print_line "Subcommands:"
    print_line "  add - add a DNS resolution entry to resolve certain domain names through a particular DNS server"
    print_line "  remove - delete a DNS resolution entry; 'del' is an alias"
    print_line "  purge - remove all DNS resolution entries"
    print_line "  print - show all active DNS resolution entries"
    print_line
    print_line "Examples:"
    print_line "  Display all current DNS nameserver entries"
    print_line "    dns"
    print_line "    dns print"
    print_line
    print_line "  Set the DNS server(s) to be used for *.metasploit.com to 192.168.1.10"
    print_line "    route add --rule *.metasploit.com 192.168.1.10"
    print_line
    print_line "  Add multiple entries at once"
    print_line "    route add --rule *.metasploit.com --rule *.google.com 192.168.1.10 192.168.1.11"
    print_line
    print_line "  Set the DNS server(s) to be used for *.metasploit.com to 192.168.1.10, but specifically to go through session 2"
    print_line "    route add --session 2 --rule *.metasploit.com 192.168.1.10"
    print_line
    print_line "  Delete the DNS resolution rule with ID 3"
    print_line "    route remove -i 3"
    print_line
    print_line "  Delete multiple entries in one command"
    print_line "    route remove -i 3 -i 4 -i 5"
    print_line
    print_line "  Set the DNS server(s) to be used for all requests that match no rules"
    print_line "    route add 8.8.8.8 8.8.4.4"
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
      when "remove", "del"
        remove_dns(*args)
      when "purge"
        purge_dns
      when "print"
        print_dns
      when "help"
        cmd_dns_help
      else
        print_error("Invalid command. To view help: dns -h")
      end
    rescue ::ArgumentError => e
      print_error(e.message)
    end
  end

  def add_dns(*args)
    rules = []
    comm = nil
    servers = []
    @@add_opts.parse(args) do |opt, idx, val|
      unless servers.empty? || opt.nil?
        raise ::ArgumentError.new("Invalid command near #{opt}")
      end
      case opt
      when '--rule', '-r'
        raise ::ArgumentError.new('No rule specified') if val.nil?

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
    end

    # Split each DNS server entry up into a separate entry
    servers.each do |server|
      driver.framework.dns_resolver.add_nameserver(rules, server, comm_obj)
    end
    print_good("#{servers.length} DNS #{servers.length > 1 ? 'entries' : 'entry'} added")
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
  # Delete all user-configured DNS settings
  #
  def purge_dns
    driver.framework.dns_resolver.purge
    print_good('DNS entries purged')
  end

  #
  # Display the user-configured DNS settings
  #
  def print_dns
    results = driver.framework.dns_resolver.nameserver_entries
    columns = ['ID','Rule(s)', 'DNS Server', 'Comm channel']
    print_dns_set('Custom nameserver rules', results[0])

    # Default nameservers don't include a rule
    columns = ['ID', 'DNS Server', 'Comm channel']
    print_dns_set('Default nameservers', results[1])

    print_line('No custom DNS nameserver entries configured') if results[0].length + results[1].length == 0
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
    if result_set[0][:wildcard_rules].any?
      columns = ['ID', 'Rules(s)', 'DNS Server', 'Comm channel']
    else
      columns = ['ID', 'DNS Server', 'Commm channel']
    end

    tbl = Table.new(
        Table::Style::Default,
        'Header'  => heading,
        'Prefix'  => "\n",
        'Postfix' => "\n",
        'Columns' => columns
        )
    result_set.each do |hash|
      if columns.size == 4
        tbl << [hash[:id], hash[:wildcard_rules].join(','), hash[:dns_server], prettify_comm(hash[:comm], hash[:dns_server])]
      else
        tbl << [hash[:id], hash[:dns_server], prettify_comm(hash[:comm], hash[:dns_server])]
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