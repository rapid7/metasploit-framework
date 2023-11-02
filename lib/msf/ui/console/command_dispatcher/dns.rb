# -*- coding: binary -*-

class Msf::Ui::Console::CommandDispatcher::DNS

  include Msf::Ui::Console::CommandDispatcher

  @@add_opts = Rex::Parser::Arguments.new(
    ['-r', '--rule'] => [true, 'Set a DNS wildcard entry to match against' ],
    ['-s', '--session'] => [true, 'Force the DNS request to occur over a particular channel (override routing rules)' ],
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
        purge_dns(*args)
      when "print"
        print_dns(*args)
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
        if val.nil?
          raise ::ArgumentError.new('No rule specified')
        end

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
      unless host =~ Resolv::IPv4::Regex || 
             host =~ Resolv::IPv6::Regex
        raise ::ArgumentError.new("Invalid DNS server: #{host}")
      end
    end
  end

  def remove_dns(*args)
  end

  def purge_dns(*args)
  end

  def print_dns(*args)
  end
end
