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

  def cmd_dns_help
    print_line 'Usage: dns'
    print_line
    print_line "Manage Metasploit's DNS resolution behaviour"
    print_line
    print_line "Usage:"
    print_line "  dns [add/remove] [--session <session_id>] [--rule <wildcard DNS entry>] <IP Address> <IP Address> ..."
    print_line "  dns [get] <hostname>"
    print_line "  dns [flush]"
    print_line "  dns [print]"
    print_line
    print_line "Subcommands:"
    print_line "  add - add a DNS resolution entry to resolve certain domain names through a particular DNS server"
    print_line "  remove - delete a DNS resolution entry; 'del' is an alias"
    print_line "  flush - remove all DNS resolution entries"
    print_line "  get - display the DNS server(s) and communication channel that would be used for a given target"
    print_line "  print - show all active DNS resolution entries"
    print_line
    print_line "Examples:"
    print_line "  Set the DNS server to be used for *.metasploit.com to 192.168.1.10"
    print_line "    route add --rule *.metasploit.com 192.168.1.10"
    print_line
    print_line "  Set the DNS server to be used for *.metasploit.com to 192.168.1.10, but specifically to go through session 2"
    print_line "    route add --session 2 --rule *.metasploit.com 192.168.1.10"
    print_line
    print_line "  Delete the above DNS resolution rule"
    print_line "    route remove --session 2 --rule *.metasploit.com 192.168.1.10"
    print_line
    print_line "  Set the DNS server to be used for all requests that match no rules"
    print_line "    route add 8.8.8.8 8.8.4.4"
    print_line
    print_line "  Display the DNS server that would be used for the given domain name"
    print_line "    route get subdomain.metasploit.com"
    print_line
  end

  #
  # Manage Metasploit's DNS resolution rules
  #
  def cmd_dns(*args)
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

    # Split each DNS server entry up into a separate entry
    servers.each do |server|
      driver.framework.dns_resolver.add_nameserver(rules, server, comm_obj)
    end
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

    driver.framework.dns_resolver.remove_ids(remove_ids)
  end

  #
  # Delete all user-configured DNS settings
  #
  def purge_dns
    driver.framework.dns_resolver.purge
  end

  #
  # Display the user-configured DNS settings
  #
  def print_dns
    results = driver.framework.dns_resolver.nameserver_entries
    columns = ['ID','Rule(s)', 'DNS Server(s)', 'Comm channel']
    print_dns_set('Custom nameserver rules', columns, results[0].map {|hash| [hash[:id], hash[:wildcard_rules].join(','), hash[:dns_server], prettify_comm(hash[:comm], hash[:dns_server])]})

    # Default nameservers don't include a rule
    columns = ['ID', 'DNS Server(s)', 'Comm channel']
    print_dns_set('Default nameservers', columns, results[1].map {|hash| [hash[:id], hash[:dns_server], prettify_comm(hash[:comm], hash[:dns_server])]})
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

  def print_dns_set(heading, columns, result_set)
    tbl = Table.new(
        Table::Style::Default,
        'Header'  => heading,
        'Prefix'  => "\n",
        'Postfix' => "\n",
        'Columns' => columns
        )
    result_set.each do |row|
      tbl << row
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